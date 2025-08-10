# AF_XDP Library Migration Guide

## 函數對照表

### 原始版本 vs 重構版本

| 原始函數 | 重構函數 | 主要變化 |
|----------|----------|----------|
| `configure_xsk_umem()` | `af_xdp_configure_umem()` | 增加前綴，無其他變化 |
| `xsk_configure_socket()` | `af_xdp_configure_socket()` | 增加前綴，新增參數 |
| `xsk_alloc_umem_frame()` | `af_xdp_alloc_umem_frame()` | 增加前綴，無其他變化 |
| `xsk_free_umem_frame()` | `af_xdp_free_umem_frame()` | 增加前綴，無其他變化 |
| `xsk_umem_free_frames()` | `af_xdp_umem_free_frames()` | 增加前綴，無其他變化 |
| `complete_tx()` | `af_xdp_complete_tx()` | 增加前綴，無其他變化 |
| `process_packet()` | `af_xdp_process_packet()` | 增加前綴，無其他變化 |
| `handle_receive_packets()` | `af_xdp_handle_receive_packets()` | 增加前綴，無其他變化 |
| `rx_and_process()` | `af_xdp_rx_and_process()` | 增加前綴，新增參數 |
| `gettime()` | `af_xdp_gettime()` | 增加前綴，無其他變化 |
| `calc_period()` | `af_xdp_calc_period()` | 增加前綴，無其他變化 |
| `stats_print()` | `af_xdp_stats_print()` | 增加前綴，無其他變化 |
| `stats_poll()` | `af_xdp_stats_poll()` | 增加前綴，無其他變化 |

## 主要設計變更

### 1. 函數簽名變化

#### `xsk_configure_socket` → `af_xdp_configure_socket`
```c
// 原始版本
static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
                                                    struct xsk_umem_info *umem);

// 重構版本  
struct xsk_socket_info *af_xdp_configure_socket(struct config *cfg,
                                                struct xsk_umem_info *umem,
                                                int xsk_map_fd,
                                                bool custom_xsk);
```

**變化說明：**
- 移除 `static` 關鍵字，使函數可以被外部調用
- 新增 `xsk_map_fd` 參數，取代全局變數
- 新增 `custom_xsk` 參數，取代全局變數
- 增加 `af_xdp_` 前綴

#### `rx_and_process` → `af_xdp_rx_and_process`
```c
// 原始版本
static void rx_and_process(struct config *cfg,
                          struct xsk_socket_info *xsk_socket);

// 重構版本
void af_xdp_rx_and_process(struct config *cfg, 
                          struct xsk_socket_info *xsk_socket,
                          bool *global_exit);
```

**變化說明：**
- 移除 `static` 關鍵字
- 新增 `global_exit` 參數，取代全局變數
- 增加 `af_xdp_` 前綴

### 2. 新增的高階 API

重構版本新增了一系列高階 API，讓使用更加簡單：

```c
// 上下文管理
struct af_xdp_context *af_xdp_init(void);
void af_xdp_cleanup(struct af_xdp_context *ctx);

// 設置函數
int af_xdp_setup_program(struct af_xdp_context *ctx, const char *filename, const char *progname);
int af_xdp_setup_socket(struct af_xdp_context *ctx);
int af_xdp_start_stats_thread(struct af_xdp_context *ctx);

// 工具函數
void af_xdp_set_global_exit(struct af_xdp_context *ctx, bool exit_flag);
bool af_xdp_should_exit(struct af_xdp_context *ctx);
```

### 3. 全局變數的處理

| 原始全局變數 | 重構後的處理方式 |
|-------------|------------------|
| `prog` | 移到 `af_xdp_context` 結構中 |
| `xsk_map_fd` | 移到 `af_xdp_context` 結構中 |
| `custom_xsk` | 移到 `af_xdp_context` 結構中 |
| `global_exit` | 移到 `af_xdp_context` 結構中 |
| `cfg` | 移到 `af_xdp_context` 結構中 |

## 使用範例

### 原始版本使用方式
```c
// 需要手動管理全局變數和資源
struct config cfg;
struct xsk_umem_info *umem;
struct xsk_socket_info *xsk_socket;

// 手動設置和清理
```

### 重構版本使用方式
```c
#include "af_xdp_lib.h"

// 簡化的使用方式
struct af_xdp_context *ctx = af_xdp_init();
ctx->cfg.ifindex = if_nametoindex("eth0");
strcpy(ctx->cfg.ifname, "eth0");

af_xdp_setup_socket(ctx);
af_xdp_start_stats_thread(ctx);
af_xdp_rx_and_process(&ctx->cfg, ctx->xsk_socket, &ctx->global_exit);

af_xdp_cleanup(ctx);  // 自動清理所有資源
```

## 總結

重構版本的主要優勢：
1. **模組化設計**：所有函數都有統一的命名前綴
2. **更好的封裝**：全局變數被封裝在上下文結構中
3. **簡化的資源管理**：自動化的初始化和清理
4. **更靈活的參數傳遞**：減少對全局狀態的依賴
5. **更好的可重用性**：可以被其他項目輕鬆集成

所有原始函數的功能都被保留，只是以更結構化的方式重新組織。
