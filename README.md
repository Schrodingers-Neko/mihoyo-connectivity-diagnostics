# 米哈游国服网络连通性诊断与加速器选购评估工具

[简体中文](README.md) | [English](README.en.md)

专为海外连接**米哈游国服** (miHoYo China Server) 玩家（*原神*、*崩坏：星穹铁道*、*绝区零*、*崩坏3*）设计的轻量化、持续性网络诊断套件与加速器选购决策引擎。

本工具通过多区域并发差分探测，实时测量本地网络、跨洋骨干网与米哈游国服集群的往返时延（RTT）、抖动（Jitter）、丢包率及 TCP 握手耗时，自动关联中国晚高峰骨干网拥堵时段，基于客观数据科学评估是否有必要付费订购游戏加速器（如网易UU、雷神加速器等）。

---

## 架构与工作原理

```
mihoyo_connectivity_diagnostics/
├── config.json            # 目标节点、采样周期与故障阈值配置
├── game_discovery.py      # 免依赖、跨盘符的国服游戏进程检测模块
├── find_game_ip.py        # 实时游戏连接与服务器套接字检测 CLI
├── monitor.py             # 异步多区域持续网络监控守护程序
├── analyze.py             # 决策引擎与双语可视化 HTML 报告生成器
├── README.md              # 简体中文说明文档 (默认)
├── README.en.md           # 英文说明文档
├── logs/                  # 包含时间戳的 CSV 原始日志 (connectivity_YYYYMMDD_HHMMSS.csv)
├── traces/                # 异常触发式后台自动路由追踪快照 (tracert)
└── reports/               # 双语交互式 HTML 诊断报告 (summary_latest.html)
```

### 三区域差分诊断架构 (Differential Diagnostics)
为了在出现卡顿时精准定责（究竟是玩家家里 Wi-Fi 不好、跨洋海缆受损，还是中国公共骨干网拥堵），本工具每轮周期同时并发探测三个基准区域：

1. **第 1 区：本地与局域网控制组 (Zone 1 - Local Control)**:
   - 目标：本地局域网网关（自动识别路由器如 `192.168.1.1` 或 `192.168.x.1`）与 Cloudflare 顶级公共 DNS (`1.1.1.1`)。
   - 作用：定责是否因本地 Wi-Fi 信号衰减、路由器缓冲区膨胀（Bufferbloat）或本地光猫故障导致丢包。
2. **第 2 区：跨洋中继控制组 (Zone 2 - Asia Transit Control)**:
   - 目标：东亚/东京枢纽控制节点 (`20.210.150.1` 微软 Azure 东京数据中心)。
   - 作用：定责横跨太平洋的海底光缆是否存在国际大面积断网、海缆中断或绕路欧洲。
3. **第 3 区：米哈游国服生产节点 (Zone 3 - miHoYo China Production)**:
   - 目标：阿里云 BGP 高防 IP (`203.107.36.87`, `203.107.60.77`)、昆仑 CDN 调度节点 (`122.156.129.54`)，以及当前正在游玩的国服游戏实时通信套接字。
   - 作用：精准测定跨越中国国际出口关口局时的真实丢包与延迟跳变。

### 监控的米哈游国服游戏进程
程序直接通过 Windows 进程池进行免盘符检测，无需指定具体的安装盘符（无论安装在 `C:`、`D:`、移动固态硬盘或第三方客户端均可自动识别）：
* **原神 (国服)**: `YuanShen.exe` *(国际服客户端 `GenshinImpact.exe` 已被排除)*
* **崩坏：星穹铁道 (国服)**: `StarRail.exe`
* **绝区零 (国服)**: `ZenlessZoneZero.exe`
* **崩坏3 (国服)**: `BH3.exe` *(国际服客户端 `Honkai Impact 3rd.exe` 已被排除)*

---

## 快速上手

### 1. 运行环境
本项目基于 Python 3.13 与 `uv`（已配置完毕）。核心诊断脚本基于 Python 标准库，**无需强制安装任何第三方依赖**，即可原生运行：

```powershell
# 激活虚拟环境（可选）
.venv\Scripts\activate
```

### 2. 运行单次诊断自检
快速执行一轮完整自检，打印终端表格并验证各节点连通性：

```powershell
python monitor.py --test-once
```

### 3. 查看当前游戏运行状态与实时服务器 IP
启动游戏（如原神、星铁、绝区零或崩坏3）后，运行：

```powershell
# 单次检测当前运行中的游戏及远程连接
python find_game_ip.py

# 持续刷新监听（每 3 秒刷新一次）
python find_game_ip.py --watch

# 自动将侦测到的活跃游戏服务器节点追加到 config.json 监控列表中
python find_game_ip.py --add-to-config
```

### 4. 启动持续性后台监控
启动持续监控探针。每次启动均会自动在 `logs\` 目录下创建带有时间戳的独立 CSV 文件（例如 `logs\connectivity_YYYYMMDD_HHMMSS.csv`），默认每 20 秒并发探测一次：

```powershell
python monitor.py
```

支持手动指定日志路径：
```powershell
python monitor.py --log logs\my_session.csv
```

#### 在后台静默运行（推荐）
在 PowerShell 中以后台静默进程形式启动，不占用当前终端窗口：
```powershell
Start-Process -FilePath "python.exe" -ArgumentList "monitor.py --quiet" -WindowStyle Hidden
```

需要停止后台监控时：
```powershell
Stop-Process -Name "python"
```

### 5. 生成加速器选购评估报告
在积累了数小时监控数据（或游戏游玩结束后），运行决策分析引擎：

```powershell
# 自动读取最新的监控会话并生成双语 HTML 可视化报告
python analyze.py --html

# 或者聚合 logs\ 目录下所有历史日志进行多天全量综合分析：
python analyze.py --all --html
```

分析完成后将输出：
- 终端双语客观决策评估（包含丢包原因剖析）。
- 带有时间戳的归档报告：`reports\summary_YYYYMMDD_HHMMSS.html`。
- 固定书签报告：`reports\summary_latest.html`（**默认显示简体中文，右上角提供一键切换为英文的按钮**，浏览器自动记忆语言偏好）。

---

## 加速器选购决策矩阵 (Decision Matrix)

分析引擎基于以下三原则做出客观评定，避免盲目购买或做无用功：

| 观测到的网络特征 | 根本原因分析 | 加速器选购决策结论 |
| :--- | :--- | :--- |
| **第 1、2 区纯净健康（0% 丢包）**，但第 3 区米哈游国服节点丢包率达 15% - 50%+，时延超过 350 ms，且中国晚高峰时段（北京时间 19:00 - 23:00）劣化明显。 | **公共 ChinaNet 163 国际出口严重拥堵与 GFW QoS 流量清洗审查** | **建议购买。** 加速器（网易UU/雷神）具备专有企业级跨洋专线（CN2 GIA / AS9929 / SD-WAN），能直接绕过公共 163 骨干网瓶颈，将丢包降至接近 0%，时延锁定在光速物理极限（根据海外距离约 160 - 200 ms）。 |
| **第 1 区（本地网关）丢包 ≥ 5% 或抖动剧烈**，同时伴随游戏卡顿。 | **本地 Wi-Fi 穿墙信号弱、路由器负荷过高或光猫线路故障** | **无需购买（本地故障）。** 任何游戏加速器都无法解决本地局域网物理丢包。建议优先更换网线连接或重启光猫/路由器。 |
| **所有国际路由节点通畅**，但米哈游目标节点无差别 100% 超时且持续 15 - 30 分钟。 | **米哈游服务器端停机维护，或阿里云高防清洗中心进入硬防黑洞** | **无需购买（服务端事件）。** 服务器当前拒绝接收一切外部入站流量，加速器同样无法连接。 |

---

## `traces/` 目录说明

`traces/` 目录用于存储**事件触发式的故障路由追踪快照**：

* **设计初衷：** 若每隔 20 秒执行一次 `tracert` 会占用大量带宽且耗时 30 - 60 秒。因此在正常状况下，程序仅使用极轻量的并发 ICMP 与非阻塞 TCP 探测。
* **触发机制：** 当米哈游国服边缘节点发生异常（丢包率 ≥ 20% 或时延 ≥ 300 ms），且本地局域网健康时，探针判定发生了**严重跨洋路由劣化事件**。
* **快照记录：** 探针将在后台静默拉起 `tracert -d` 追踪路由，并将跳数详情保存为 `traces\trace_YYYYMMDD_HHMMSS_<target>_<ip>.txt`（内置 5 分钟冷却期防重复触发）。
* **取证价值：** 当向 ISP 运营商反馈报障，或向加速器客服反馈线路异常时，可直接打开快照文件，精准查看数据包是在哪个自治系统（AS）或节点（如中国电信 `202.97.*.*` 163 骨干网出入口）发生超时或延迟翻倍。

---

## 配置文件说明 (`config.json`)

```json
{
  "tracked_games": [
    {
      "name": "原神 (Genshin Impact CN)",
      "executables": ["YuanShen.exe"],
      "server_ports": [22101, 22102]
    },
    {
      "name": "崩坏：星穹铁道 (Honkai: Star Rail CN)",
      "executables": ["StarRail.exe"],
      "server_ports": []
    },
    {
      "name": "绝区零 (Zenless Zone Zero CN)",
      "executables": ["ZenlessZoneZero.exe"],
      "server_ports": []
    },
    {
      "name": "崩坏3 (Honkai Impact 3rd CN)",
      "executables": ["BH3.exe"],
      "server_ports": []
    }
  ],
  "sampling": {
    "interval_seconds": 20,
    "ping_burst_count": 5,
    "ping_timeout_ms": 1000,
    "tcp_timeout_ms": 2000
  },
  "targets": {
    "local_gateway": "auto",
    "global_control": "1.1.1.1",
    "asia_transit_control": "20.210.150.1",
    "mihoyo_endpoints": [
      { "name": "Aliyun-AntiDDoS-1", "host": "203.107.36.87", "port": 443 },
      { "name": "Aliyun-AntiDDoS-2", "host": "203.107.60.77", "port": 443 },
      { "name": "Kunlun-CDN", "host": "122.156.129.54", "port": 80 }
    ]
  },
  "anomaly_trigger": {
    "loss_threshold_pct": 20.0,
    "rtt_spike_threshold_ms": 80.0,
    "trace_cooldown_seconds": 300,
    "max_hops": 25
  },
  "paths": {
    "log_file_template": "logs/connectivity_{timestamp}.csv",
    "trace_dir": "traces",
    "report_dir": "reports",
    "report_file_template": "reports/summary_{timestamp}.html"
  }
}
```
