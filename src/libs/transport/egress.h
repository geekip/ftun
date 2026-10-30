#ifndef FTUN_LIBS_TRANSPORT_EGRESS_H
#define FTUN_LIBS_TRANSPORT_EGRESS_H
#include "libs/transport/path.h"

/* 出口（Egress）：「经哪条路到达目标」的协议无关接口。
 *
 * 消费方（DNS 上游、HTTP 拉取、控制端点解析、将来的 Mesh 控制面）只持有
 * 出口编号，把最终目标交给出口打开 Path；出口实现负责其余一切：
 * 物理直连、代理握手、UDP 封装、组成员选择、
 * 经 Mesh 节点转发。消费方不得读取、比较或分支出口的种类。
 *
 * 提供方：直连由 libs/transport 提供（ftun_egress_direct_provider）；
 * 代理出站由 proxy 模块提供；Mesh 节点通道由 mesh 模块提供。
 * 三者由 app 装配成一个提供者交给消费方；各业务互不引用。
 *
 * 失败语义：出口不可用时打开失败，
 * 任何实现都不得自行改走直连或其他出口。 */

typedef uint32_t ftun_egress_id_t;
/* 零值即直连，与零初始化的 ftun_path_open_request_t 一致。 */
#define FTUN_EGRESS_DIRECT ((ftun_egress_id_t)0u)
#define FTUN_EGRESS_NONE ((ftun_egress_id_t)UINT32_MAX)

/* 能力位只描述「能做什么」，不暴露「是什么」。 */
#define FTUN_EGRESS_CAP_STREAM 0x01u        /* 可打开字节流 */
#define FTUN_EGRESS_CAP_DATAGRAM 0x02u      /* 可打开报文通道 */
#define FTUN_EGRESS_CAP_DOMAIN_TARGET 0x04u /* 可把域名目标交给对端解析 */
#define FTUN_EGRESS_CAP_OVERLAY 0x08u       /* 经虚拟网络到达，不占用物理出口 */

typedef enum {
  FTUN_EGRESS_STATE_UNKNOWN = 0,
  FTUN_EGRESS_STATE_AVAILABLE,
  FTUN_EGRESS_STATE_DEGRADED,
  FTUN_EGRESS_STATE_UNAVAILABLE
} ftun_egress_state_t;

typedef struct {
  ftun_egress_id_t id;
  uint32_t capabilities;
  /* 消费方按出口声明的解析源名选择DNS服务，不解释出口种类。 */
  ftun_string_t resolver;
  ftun_egress_state_t state;
  /* 编号只在这一配置代次内有效。 */
  uint64_t configuration_generation;
  /* 仅供日志与状态查询的静态字符串（"direct"、"proxy"、"mesh"）。
   * 消费方不得据此分支；需要行为差异时增加能力位。 */
  const char *provider_kind;
} ftun_egress_info_t;

typedef struct {
  /* 配置期：把配置里的出口名解析成编号与能力。只读 config，不分配、
   * 不做 I/O，可在配置检查阶段调用。未知名字返回 FTUN_E_REJECTED，
   * 已知但本构建未内置（例如 proxy 模块关闭）返回 FTUN_E_UNSUPPORTED。 */
  ftun_status_t (*resolve)(const void *context, const ftun_config_t *config,
                           ftun_string_t name, ftun_egress_info_t *out);
  /* 运行期：查询可用性，用于状态展示和消费方的选择策略。
   * 代次不符返回 FTUN_E_STALE。不阻塞，不触发探测。 */
  ftun_status_t (*query)(const void *context, ftun_egress_id_t egress,
                         uint64_t configuration_generation,
                         ftun_egress_info_t *out);
  /* 运行期：与 ftun_path_provider_ops_t.open 同签名，可直接作为
   * Path Provider 的工厂；出口编号取自 request->egress。
   *
   * 交付的 Path 对调用方等价于「直连 request->dial.endpoint」：
   * - 流：出口握手已完成，读写的就是与最终目标之间的字节；
   * - 报文：send 的目标与 receive 的来源都是最终目标地址，
   *   封装与解封由出口实现完成，调用方照常校验来源；
   * - result_spec.endpoint 是最终目标，而不是代理服务器或中继。
   *
   * 授权：Provider 已用 request->dial 授权最终目标；出口实现到代理或
   * 中继的物理连接必须另行发起并授权（ftun_dial_start），沿用
   * request->dial.protection 的出口保护，不得放宽。
   *
   * 同步失败零回调；REJECT 类出口同步返回 FTUN_E_REJECTED；
   * 编号与 result_spec->configuration_generation 不属于同一代次时
   * 返回 FTUN_E_STALE。成功后的完成、取消契约与 Path 工厂相同。 */
  ftun_status_t (*open)(void *context, ftun_core_t *core,
                        const ftun_path_open_request_t *request,
                        const ftun_path_spec_t *result_spec,
                        ftun_operation_t **out);
  void *context;
  /* 动态配置快照的引用钩子；均为空表示进程寿命的静态提供者。
   * retain/release 必须可跨 worker 使用，不能访问可变的主循环状态。 */
  void (*retain)(void *context);
  void (*release)(void *context);
  /* 验证已固定叶子仍属于原出口；不重新选择活动组。 */
  ftun_status_t (*validate)(const void *context, ftun_egress_id_t root,
    ftun_egress_id_t leaf, uint64_t generation);
} ftun_egress_provider_t;

void ftun_egress_retain(const ftun_egress_provider_t *provider);
void ftun_egress_release(const ftun_egress_provider_t **provider);

/* 只认 FTUN_EGRESS_DIRECT 的提供者：名字 "DIRECT"，打开时转给物理
 * socket 工厂。没有 proxy、mesh 的构建直接使用它。静态对象，无需销毁。 */
const ftun_egress_provider_t *ftun_egress_direct_provider(void);

/* 把提供者包装成 Path Provider 工厂：ops.open = ftun_egress_path_open，
 * context = 提供者指针（借用，寿命须覆盖 Provider 与全部 Path）。 */
ftun_status_t ftun_egress_path_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *result_spec,
  ftun_operation_t **out);

/* 便捷检查：出口是否具备本次传输需要的能力。 */
bool ftun_egress_supports(const ftun_egress_info_t *info,
                          ftun_dial_transport_t transport);

#endif
