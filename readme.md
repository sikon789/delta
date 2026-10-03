# Delta Platoboost solver (8.1.1) — Windows 部署

## 1. 环境

- Windows Server 2016/2019/2022 或 Win10/11
- Python **3.10+**（建议 3.11）  
  https://www.python.org/downloads/windows/  
  安装时勾选 **Add python.exe to PATH**
- 出网 HTTPS：`auth.platorelay.com`、`api.platoboost.net`

`uvloop` 在 Windows 上会自动跳过，不影响功能。

## 2. 安装

解压 zip，在目录里双击或管理员 CMD：

```bat
install.bat
```

等价手动：

```bat
py -3 -m venv .venv
.venv\Scripts\activate
python -m pip install -U pip
python -m pip install -r requirements.txt
```

## 3. 命令行求解

```bat
start-cli.bat "https://auth.platorelay.com/a?d=TICKET"
start-cli.bat --generate 1
start-cli.bat ticket.txt
```

成功会打印 `DELTA KEY`。

默认 **尽量避开 Discord**：一检测到 `account-unlock-required` 立刻停，自动换随机 HWID 再求一把 key（`--fresh`，默认开）。

注意：新 key 绑的是**新 identifier**，填不进已经锁死的那台 Delta 设备。只要原设备的 key，必须 `--no-fresh` 再自己走 Discord。

```bat
start-cli.bat --no-fresh "https://auth.platorelay.com/a?d=LOCKTICKET"
```

HTTP API 同样：锁票会换新 HWID 再求；换出来的 key **不会**缓存到原链接上。

## 4. HTTP API（给其他人调用）

```bat
start-api.bat
```

默认 `0.0.0.0:2233`。

```
GET http://127.0.0.1:2233/delta?url=https://auth.platorelay.com/a?d=TICKET
```

返回 JSON：`key` / `error` / `cached` / `times`。

本机测通后再开防火墙：

```bat
netsh advfirewall firewall add rule name="Delta Cardkey 2233" dir=in action=allow protocol=TCP localport=2233
```

只内网用就把 `start-api.bat` 里 `HOST=0.0.0.0` 改成 `127.0.0.1`，不要映射公网。

改端口：`python server.py --port 8080 --workers 10`

## 5. 开机自启（API）

用任务计划，掉线会拉起来：

```bat
schtasks /Create /TN "DeltaCardkey" /SC ONSTART /RL HIGHEST /RU SYSTEM ^
  /TR "C:\delta-key\.venv\Scripts\python.exe C:\delta-key\server.py --host 0.0.0.0 --port 2233 --workers 10"
```

把路径换成你的解压目录。查看/删：

```bat
schtasks /Query /TN "DeltaCardkey" /V /FO LIST
schtasks /Delete /TN "DeltaCardkey" /F
```

要做 Windows 服务可以用 [NSSM](https://nssm.cc/)：

```bat
nssm install DeltaCardkey C:\delta-key\.venv\Scripts\python.exe
nssm set DeltaCardkey AppParameters "C:\delta-key\server.py --host 0.0.0.0 --port 2233 --workers 10"
nssm set DeltaCardkey AppDirectory C:\delta-key
nssm set DeltaCardkey AppStdout C:\delta-key\api.log
nssm set DeltaCardkey AppStderr C:\delta-key\api.err
nssm start DeltaCardkey
```

## 6. 文件

| 文件 | 作用 |
|---|---|
| `main.py` | CLI |
| `server.py` | FastAPI |
| `auth_client.py` | 8.1.1 协议 |
| `link_generator.py` | `--generate` |
| `requirements.txt` | 依赖 |
| `.key_cache.json` | API 跑起来后自动生成，同 ticket 24h 缓存 |

## 7. 常见问题

- `outdated client`：确认 `auth_client.py` 里 `FALLBACK_VERSION = "8.1.1"`
- `account-unlock-required`：这张票要 Discord/Google，换 `--generate`
- 防火墙出站 443 被拦：服务器访问不了 Platoboost
- 杀软拦 pycryptodome / python：加目录白名单
## 8. 致谢
- 感谢Hals team 提供的源码，由胖猫Hub改进
