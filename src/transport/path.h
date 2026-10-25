#ifndef FTUN_TRANSPORT_PATH_H
#define FTUN_TRANSPORT_PATH_H

#include "transport/dialer.h"
#include "transport/stream.h"
#include "transport/datagram.h"

typedef struct ftun_path_provider ftun_path_provider_t;
typedef struct ftun_path ftun_path_t;
typedef struct ftun_path_scope ftun_path_scope_t;

typedef struct {
  /* 停止事件来源，不释放通道后端；失败保留全部句柄，可重复调用。 */
  ftun_status_t (*stop)(void *context);
  /* 恢复因接收背压或资源不足暂停的输入，不内联调用消费者。 */
  ftun_status_t (*resume)(void *context);
  void *context;
  /* 可选本地端点查询；没有物理地址的通道返回 UNSUPPORTED。 */
  ftun_status_t (*local_endpoint)(void *context, ftun_endpoint_t *out);
} ftun_path_driver_t;

typedef struct {
  ftun_budget_t *budget;
  uint64_t configuration_generation;
  uint64_t path_generation;
  /* 非空时保留实际对象；网络代次从 View 读取，不由配置代次推断。 */
  ftun_network_view_t *network_view;
  ftun_endpoint_t endpoint;
  ftun_dial_purpose_t purpose;
  ftun_dial_domain_t domain;
  /* 可选驱动借用通道后端状态，直到通道 destroy；stop 必须先成功。 */
  ftun_path_driver_t driver;
  /* 可选共享接收池；与 budget 同根且同 owner，由宿主持有至通道及所有
   * 接收报文引用释放。工厂可以忽略，不得借它放宽路径授权。 */
  ftun_buffer_pool_t *receive_pool;
} ftun_path_spec_t;

typedef struct {
  uint64_t configuration_generation;
  uint64_t path_generation;
  uint64_t network_generation;
  /* View 和 endpoint.domain 的存储仅借用，寿命由所持 Path 引用保证。 */
  const ftun_network_view_t *network_view;
  ftun_endpoint_t endpoint;
  ftun_dial_purpose_t purpose;
  ftun_dial_domain_t domain;
  ftun_dial_transport_t transport;
  size_t references;
  bool revoked;
} ftun_path_info_t;

/* 接管工厂已经建立且空闲的通道，不执行路由或替代 Provider 的权限检查。
 * 成功消费 *channel 并清零；失败保留通道，清零 out，不执行任何回调。
 * Stream 必须只有创建者引用；两类通道必须仍接纳且无在途发送/回调。
 * Path 保留一个创建者引用，额外引用用 retain/release；初始引用由 destroy
 * 消费。revoke/destroy 的后端回调期间不能新增 Path 引用（返回 AGAIN）。
 * 全部调用属于同一 owner，禁止跨线程读写 Path/通道/View 引用计数。 */
ftun_status_t ftun_path_adopt_stream(const ftun_path_spec_t *spec,
  ftun_stream_t **channel, ftun_path_t **out);
ftun_status_t ftun_path_adopt_datagram(const ftun_path_spec_t *spec,
  ftun_datagram_t **channel, ftun_path_t **out);
ftun_status_t ftun_path_retain(ftun_path_t *path);
ftun_status_t ftun_path_release(ftun_path_t **path);
ftun_status_t ftun_path_get_info(const ftun_path_t *path, ftun_path_info_t *out);
/* 通道仅借用；其拥有权不得从 Path 再次移走。额外 Stream 引用可以保留，
 * 但必须在 Path destroy 成功前释放；Datagram 借用不得超出 Path 引用寿命。 */
ftun_status_t ftun_path_stream(ftun_path_t *path, ftun_stream_t **out);
ftun_status_t ftun_path_datagram(ftun_path_t *path, ftun_datagram_t **out);
/* 标记撤销并关闭读写，尝试取消在途发送。失败仍保持 revoked 与通道所有权，
 * 允许下一轮重试；不得停止共享队列或主动 dispatch。正在回调中重入为 AGAIN。 */
ftun_status_t ftun_path_revoke(ftun_path_t *path);
/* 必须 revoked、仅剩创建者引用且通道静默。失败保留 Path 和通道供重试。
 * 即使没有在途发送，Stream 完成派发前也不能销毁；不会隐式停止共享队列。 */
ftun_status_t ftun_path_destroy(ftun_path_t **path);
ftun_status_t ftun_path_resume(ftun_path_t *path);
ftun_status_t ftun_path_local_endpoint(ftun_path_t *path, ftun_endpoint_t *out);

#define FTUN_PATH_READABLE 1u
#define FTUN_PATH_WRITABLE 2u
#define FTUN_PATH_ERROR 4u
/* owner 事件通知；Path 在回调期间持有额外引用，不能在其中销毁。
 * READABLE 提示读取 Stream，WRITABLE 提示可重试准入；Datagram 仍由其
 * receive 回调交付。ERROR 包含失败原因，恢复性 LIMIT 可在释放资源后 resume。 */
typedef void (*ftun_path_notify_fn)(ftun_path_t *path, uint32_t events,
  ftun_error_t error, void *user);

/* completion 只由 owner Operation dispatch 调用。成功转移 Path 的创建者
 * 引用；失败给用户 NULL。后端传入的非空 Path 即使伴随错误也交由 Provider
 * 回收，不能在 callback 后继续访问。 */
typedef void (*ftun_path_completion_fn)(ftun_operation_t *operation,
  ftun_error_t error, ftun_path_t *path, void *user);

typedef struct {
  /* 物理输入提供共同授权和调度参数；completion/user 必须为 NULL。 */
  ftun_dial_request_t dial;
  ftun_stream_options_t stream;
  ftun_datagram_options_t datagram;
  ftun_path_completion_fn completion;
  void *user;
  ftun_path_notify_fn notify;
  void *notify_user;
} ftun_path_open_request_t;

typedef struct {
  ftun_status_t (*start)(void *context, ftun_core_t *core,
                         const ftun_dial_request_t *request,
                         ftun_operation_t **out);
  /* 拥有型工厂：接纳前复制请求输入，零接纳失败必须零回调。
   * 成功返回 Operation，completion 必须恰好一次由该队列 dispatch 调用。
   * result_spec 及其 View 可借用至 completion 返回，含已分配的路径身份；
   * 其他请求指针只借用至 open 返回。取消使用 Operation 的 hook 契约。 */
  ftun_status_t (*open)(void *context, ftun_core_t *core,
    const ftun_path_open_request_t *request, const ftun_path_spec_t *result_spec,
    ftun_operation_t **out);
  /* 失败仍保留 pending generation，必须调用同步 reload_abort 回收；
   * reload_commit 仅允许完整 prepare 成功后调用。 */
  ftun_status_t (*reload_prepare)(void *context, uint64_t generation);
  void (*reload_commit)(void *context, uint64_t generation);
  void (*reload_abort)(void *context, uint64_t generation);
  /* 失败后接纳已关闭，但后端 quiesce 仍会在下次清理时重试。 */
  ftun_status_t (*quiesce)(void *context);
  ftun_status_t (*stop_until)(void *context, uint64_t deadline_ms);
} ftun_path_provider_ops_t;

typedef struct {
  ftun_budget_t *budget;
  uint64_t generation;
  ftun_path_provider_ops_t ops;
  /* 借用；必须比 provider、全部已接纳 operation 和已交付 Path 长寿。 */
  void *context;
  /* 零分别使用 64 / 4096；同时约束在途和已交付/待清理路径。 */
  size_t max_pending;
  size_t max_paths;
  /* 借用；传给每次工厂的 result_spec，寿命覆盖 Provider/Path/报文引用。 */
  ftun_buffer_pool_t *receive_pool;
} ftun_path_provider_spec_t;

typedef struct {
  uint64_t generation;
  uint64_t pending_generation;
  bool accepting;
  bool stopped;
  bool reload_prepared;
  size_t pending;
  size_t paths;
  size_t retired;
  size_t scopes;
} ftun_path_provider_info_t;

/* configuration_generation 只标识 Provider 的配置，不代替 NetworkView 身份。
 * dial request 的 network_generation 只约束其 network_view；没有 View 时必须
 * 为零，合法默认 Underlay 由物理拨号层继续校验。相同数字的两个 View 不等价，
 * 后端必须使用请求实际持有的 View 和 allowed 集合收窄权限。
 * 两个入口核验 transport、purpose 和 domain。成功 operation 的取消统一走
 * ftun_operation_cancel；reload 不改写已接纳请求的网络授权与完成结果。
 * Provider 的可变状态和入口调用归同一 owner。 */
ftun_status_t ftun_path_provider_create(
  const ftun_path_provider_spec_t *spec, ftun_path_provider_t **out);
ftun_status_t ftun_path_provider_open_stream(
  ftun_path_provider_t *provider, ftun_core_t *core,
  uint64_t configuration_generation,
  const ftun_dial_request_t *request, ftun_operation_t **out);
ftun_status_t ftun_path_provider_open_datagram(
  ftun_path_provider_t *provider, ftun_core_t *core,
  uint64_t configuration_generation,
  const ftun_dial_request_t *request, ftun_operation_t **out);
/* 拥有型通道入口；配置只在接纳时比较，旧操作终结不借用新配置。
 * 工厂缺席同步返回 UNSUPPORTED。stop/destroy 保留全部在途和已交付句柄。 */
ftun_status_t ftun_path_provider_open_channel(ftun_path_provider_t *provider,
  ftun_core_t *core, uint64_t configuration_generation,
  const ftun_path_open_request_t *request, ftun_operation_t **out);
/* 在当前配置代次接纳一个逻辑请求范围；后续解析/候选重试仍使用该代次。
 * scope 不放宽网络、候选或预算授权；每次 open 仍全部核验。scope 数量受
 * max_paths 约束，引用属同一 owner；禁止在 quiesce 后继续打开通道。
 * provider destroy 等待 scope 全部释放，reload 不改写已接纳 scope。 */
ftun_status_t ftun_path_provider_scope(ftun_path_provider_t *provider,
  uint64_t configuration_generation, ftun_path_scope_t **out);
ftun_status_t ftun_path_scope_retain(ftun_path_scope_t *scope);
ftun_status_t ftun_path_scope_release(ftun_path_scope_t **scope);
ftun_status_t ftun_path_scope_generation(const ftun_path_scope_t *scope, uint64_t *out);
ftun_status_t ftun_path_scope_open(ftun_path_scope_t *scope, ftun_core_t *core,
  const ftun_path_open_request_t *request, ftun_operation_t **out);

/* 标记该 View 不再授权，并按对象身份撤销此 Provider 的在途/已交付路径。
 * 失败不回滚撤销；须由 owner 重试。其他 owner 的 Provider 须分别通知。 */
ftun_status_t ftun_path_provider_revoke_network(ftun_path_provider_t *provider,
  ftun_network_view_t *view);
/* 有界尝试清理未向用户交付的结果；不 dispatch，不销毁用户持有的路径。 */
ftun_status_t ftun_path_provider_collect(ftun_path_provider_t *provider);
ftun_status_t ftun_path_provider_reload_prepare(
  ftun_path_provider_t *provider, uint64_t generation);
ftun_status_t ftun_path_provider_reload_commit(
  ftun_path_provider_t *provider, uint64_t generation);
ftun_status_t ftun_path_provider_reload_abort(ftun_path_provider_t *provider);
ftun_status_t ftun_path_provider_quiesce(ftun_path_provider_t *provider);
ftun_status_t ftun_path_provider_stop_until(
  ftun_path_provider_t *provider, uint64_t deadline_ms);
ftun_status_t ftun_path_provider_get_info(
  const ftun_path_provider_t *provider, ftun_path_provider_info_t *out);
ftun_status_t ftun_path_provider_destroy(ftun_path_provider_t **provider);

#endif
