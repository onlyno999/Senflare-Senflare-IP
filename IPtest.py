"""
Cloudflare优选IP采集器 v2.3.0
===============================================

一个高效、智能的Cloudflare优选IP采集和检测工具，专为网络优化而设计。

🎯 核心功能
-----------
• IP采集：多API源并发采集，获取大量候选IP地址
• 智能筛选：TCP连接测试快速剔除不可用IP
• 性能测试：TCP Ping延迟测试 + HTTP带宽测试
• 地区识别：自动识别IP地理位置，支持缓存机制
• 智能排序：综合延迟、带宽、稳定性进行评分排名
• 多格式输出：生成基础版和高级版IP列表文件

⚡ 技术特性
-----------
• 智能缓存：TTL机制减少重复API调用，提升效率
• 高并发处理：多线程并发检测，大幅提升速度
• 容错机制：完善的异常处理和重试策略
• 详细日志：完整的操作日志记录，支持文件输出
• 资源优化：自动缓存管理，防止内存溢出
• CI优化：针对GitHub Actions等CI环境特别优化
• 多端口支持：可配置测试端口，适应不同需求
• 评分系统：综合性能指标，智能排名推荐

📊 输出文件
-----------
• IPlist.txt - 基础版IP列表（快速筛选结果）
• Senflare.txt - 基础版格式化IP列表（按地区分组）
• IPlist-Pro.txt - 高级版IP列表（性能测试结果）
• Senflare-Pro.txt - 高级版格式化IP列表（按地区分组）
• Ranking.txt - 详细排名信息（延迟、带宽、评分）
• Cache.json - 地区信息缓存文件
• IPtest.log - 详细运行日志

🔧 配置说明
-----------
• 支持自定义测试端口、超时时间、并发数等参数
• 可开启/关闭高级模式（带宽测试、综合评分）
• 支持延迟排名筛选（取前N%的IP进行深度测试）
• 智能缓存管理，支持TTL和大小限制

作者：Senflare
版本：v2.3.0
更新：2025年10月25日
"""

# ===== 标准库导入 =====
# 正则表达式、文件操作、时间处理
import re
import os
import time
import socket
import json
import ipaddress
import logging
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# ===== 第三方库导入 =====
# HTTP请求库和SSL警告处理
import requests
from urllib3.exceptions import InsecureRequestWarning

# ===== 配置和初始化 =====

# 禁用SSL证书警告，避免HTTPS请求时的警告信息
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# 配置日志系统 - 同时输出到文件和控制台
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('IPtest.log', encoding='utf-8'),  # 文件日志
        logging.StreamHandler()  # 控制台日志
    ]
)
logger = logging.getLogger(__name__)

# ===== 核心配置 =====
# 程序运行的核心参数配置，可根据需要调整
CONFIG = {
    # 📥 IP来源配置 - 只解析这三个优选域名（用户定版，就留这三个地址）
    # 这三个域名是地域解析：权威按地区/运营商分线路返回不同 IP，
    # 靠 DoH + ECS 地域扫描（ecs_subnets.txt）把各线路的 IP 全量解出后取并集。
    "domains": [
        'cdn2.bpcdn.cc',
        'saas.sin.fan',
        'cloudflare-ip.mofashi.ltd',
        'nrt.xxxxxxxx.nyc.mn',
    ],

    # 🔍 网络测试配置
    # HTTPS标准端口: 443
    # Cloudflare专用端口: 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8443, 8444
    "test_ports": [443],                    # TCP连接测试端口（可自定义多个端口，如[443, 2052, 2053]）
    "timeout": 15,                          # IP采集超时时间（秒）
    "api_timeout": 5,                       # API查询超时时间（秒）
    "query_interval": 0.2,                 # API查询间隔时间（秒）
    
    # ⚡ 并发处理配置（GitHub Actions环境优化）
    "max_workers": 15,                      # 最大并发线程数
    "batch_size": 10,                       # 批量处理IP数量
    "cache_ttl_hours": 168,                 # 缓存有效期（7天）
    
    # 🚀 高级功能配置
    "advanced_mode": True,                  # 高级模式开关（True=开启，False=关闭）
    "bandwidth_test_count": 3,              # 带宽测试次数
    "bandwidth_test_size_mb": 10,             # 带宽测试文件大小（MB）
    "latency_filter_percentage": 30,        # 延迟排名前百分比（取前30%的IP）
}

# ===== 国家/地区映射表 =====
# 将ISO国家代码映射为中文名称，支持全球主要国家和地区
COUNTRY_MAPPING = {
    # 统一添加常见国家和地区
    # 🌎 北美地区
    'US': '美国', 'CA': '加拿大', 'MX': '墨西哥', 'CR': '哥斯达黎加', 'GT': '危地马拉', 'HN': '洪都拉斯',
    'NI': '尼加拉瓜', 'PA': '巴拿马', 'CU': '古巴', 'JM': '牙买加', 'TT': '特立尼达和多巴哥',
    'BZ': '伯利兹', 'SV': '萨尔瓦多', 'DO': '多米尼加', 'HT': '海地',
    # 🌎 南美地区
    'BR': '巴西', 'AR': '阿根廷', 'CL': '智利', 'CO': '哥伦比亚', 'PE': '秘鲁', 'VE': '委内瑞拉',
    'UY': '乌拉圭', 'PY': '巴拉圭', 'BO': '玻利维亚', 'EC': '厄瓜多尔', 'GY': '圭亚那',
    'SR': '苏里南', 'FK': '福克兰群岛',
    # 🌍 欧洲地区
    'UK': '英国', 'GB': '英国', 'FR': '法国', 'DE': '德国', 'IT': '意大利', 'ES': '西班牙', 'NL': '荷兰',
    'RU': '俄罗斯', 'SE': '瑞典', 'CH': '瑞士', 'BE': '比利时', 'AT': '奥地利', 'IS': '冰岛',
    'PL': '波兰', 'DK': '丹麦', 'NO': '挪威', 'FI': '芬兰', 'PT': '葡萄牙', 'IE': '爱尔兰',
    'UA': '乌克兰', 'CZ': '捷克', 'GR': '希腊', 'HU': '匈牙利', 'RO': '罗马尼亚', 'TR': '土耳其',
    'BG': '保加利亚', 'LT': '立陶宛', 'LV': '拉脱维亚', 'EE': '爱沙尼亚', 'BY': '白俄罗斯',
    'LU': '卢森堡', 'LUX': '卢森堡', 'SI': '斯洛文尼亚', 'SK': '斯洛伐克', 'MT': '马耳他',
    'HR': '克罗地亚', 'RS': '塞尔维亚', 'BA': '波黑', 'ME': '黑山', 'MK': '北马其顿',
    'AL': '阿尔巴尼亚', 'XK': '科索沃', 'MD': '摩尔多瓦', 'GE': '格鲁吉亚', 'AM': '亚美尼亚',
    'AZ': '阿塞拜疆', 'CY': '塞浦路斯', 'MC': '摩纳哥', 'SM': '圣马力诺', 'VA': '梵蒂冈',
    'AD': '安道尔', 'LI': '列支敦士登',
    # 🌏 亚洲地区
    'CN': '中国', 'HK': '中国香港', 'TW': '中国台湾', 'MO': '中国澳门', 'JP': '日本', 'KR': '韩国',
    'SG': '新加坡', 'SGP': '新加坡', 'IN': '印度', 'ID': '印度尼西亚', 'MY': '马来西亚', 'MYS': '马来西亚',
    'TH': '泰国', 'PH': '菲律宾', 'VN': '越南', 'PK': '巴基斯坦', 'BD': '孟加拉', 'KZ': '哈萨克斯坦',
    'IL': '以色列', 'ISR': '以色列', 'SA': '沙特阿拉伯', 'SAU': '沙特阿拉伯', 'AE': '阿联酋', 
    'QAT': '卡塔尔', 'OMN': '阿曼', 'KW': '科威特', 'BH': '巴林', 'IQ': '伊拉克', 'IR': '伊朗',
    'AF': '阿富汗', 'UZ': '乌兹别克斯坦', 'KG': '吉尔吉斯斯坦', 'TJ': '塔吉克斯坦', 'TM': '土库曼斯坦',
    'MN': '蒙古', 'NP': '尼泊尔', 'BT': '不丹', 'LK': '斯里兰卡', 'MV': '马尔代夫',
    'MM': '缅甸', 'LA': '老挝', 'KH': '柬埔寨', 'BN': '文莱', 'TL': '东帝汶',
    'LK': '斯里兰卡', 'MV': '马尔代夫', 'NP': '尼泊尔', 'BT': '不丹',
    # 🌊 大洋洲地区
    'AU': '澳大利亚', 'NZ': '新西兰', 'FJ': '斐济', 'PG': '巴布亚新几内亚', 'NC': '新喀里多尼亚',
    'VU': '瓦努阿图', 'SB': '所罗门群岛', 'TO': '汤加', 'WS': '萨摩亚', 'KI': '基里巴斯',
    'TV': '图瓦卢', 'NR': '瑙鲁', 'PW': '帕劳', 'FM': '密克罗尼西亚', 'MH': '马绍尔群岛',
    # 🌍 非洲地区
    'ZA': '南非', 'EG': '埃及', 'NG': '尼日利亚', 'KE': '肯尼亚', 'ET': '埃塞俄比亚',
    'GH': '加纳', 'TZ': '坦桑尼亚', 'UG': '乌干达', 'DZ': '阿尔及利亚', 'MA': '摩洛哥',
    'TN': '突尼斯', 'LY': '利比亚', 'SD': '苏丹', 'SS': '南苏丹', 'ER': '厄立特里亚',
    'DJ': '吉布提', 'SO': '索马里', 'ET': '埃塞俄比亚', 'KE': '肯尼亚', 'TZ': '坦桑尼亚',
    'UG': '乌干达', 'RW': '卢旺达', 'BI': '布隆迪', 'MW': '马拉维', 'ZM': '赞比亚',
    'ZW': '津巴布韦', 'BW': '博茨瓦纳', 'NA': '纳米比亚', 'SZ': '斯威士兰', 'LS': '莱索托',
    'MZ': '莫桑比克', 'MG': '马达加斯加', 'MU': '毛里求斯', 'SC': '塞舌尔', 'KM': '科摩罗',
    'CV': '佛得角', 'ST': '圣多美和普林西比', 'GW': '几内亚比绍', 'GN': '几内亚', 'SL': '塞拉利昂',
    'LR': '利比里亚', 'CI': '科特迪瓦', 'GH': '加纳', 'TG': '多哥', 'BJ': '贝宁',
    'NE': '尼日尔', 'BF': '布基纳法索', 'ML': '马里', 'SN': '塞内加尔', 'GM': '冈比亚',
    'GN': '几内亚', 'GW': '几内亚比绍', 'ST': '圣多美和普林西比', 'CV': '佛得角',
    # ❓ 其他/未知
    'Unknown': '未知'
}

# ===== 全局变量 =====
# 地区信息缓存，用于存储IP地理位置查询结果
region_cache = {}


# ===== 毒鸡汤节点名（固定 200 条） =====
# 节点显示名固定使用这 200 条毒鸡汤（用户 2026-11-21 亲发原文），顺序写死：
# 第 N 个 IP 永远配第 N 条，以后更新只换 IP、文字不动。
# 当前 IP 上限 100 个，只用到前 100 条；后 100 条是备份，以后放开上限直接续用。
# 同一个 IP 在基础版和高级版中使用同一条（按基础版顺序分配）。
FIXED_NODE_NAMES = [
    "只要你肯努力，老板明年就能换辆更好的车。",
    "别总说自己一无所有，你不是还有病吗？",
    "失败并不可怕，可怕的是你还相信这句话。",
    "很多时候你不逼自己一把，你都不知道你还有把事情搞砸的本事。",
    "咸鱼翻身，还是咸鱼，只是粘锅的程度不一样。",
    "只要我躺得够平，生活的镰刀就割不到我。",
    "别灰心，人生就是这样起起落落落落落落落的。",
    "上帝为你关上一扇门，还会顺便把窗户也焊死。",
    "努力不一定成功，但不努力一定很舒服。",
    "别整天抱怨生活苦，你才吃了几年苦？以后苦的日子还长着呢。",
    "每一个成功的男人背后，都有一个吃饱了没事干的女人；每一个失败的男人背后，都有两个。",
    "有些人表面上风风光光，背地里连双袜子都破了洞。",
    "所谓的诗和远方，不过是把眼前的苟且搬到了另一个地方。",
    "世上无难事，只要肯放弃。",
    "别再说“我真是个废物”，这对废物来说是一种侮辱。",
    "经过十年的不断奋斗，我终于从一个懵懂无知的少年，变成了一个懵懂无知的青年。",
    "当你觉得自己又丑又穷、一无是处时，别绝望，因为至少你的判断还是对的。",
    "谁说我没毅力？单身这件事，我一坚持就是二十多年。",
    "别看有些人表面上天天喊着减肥，背地里却能吃两碗大米饭。",
    "成年人的崩溃都是默不作声的，因为怕吵醒别人被骂。",
    "以前我觉得钱能解决一切问题，后来我发现，我没有钱。",
    "机会是留给有准备的人的，没有机会的人，别瞎准备了。",
    "别再熬夜了，你又没有夜生活，只是单纯地睡不着而已。",
    "别人熬夜是因为有心事，我熬夜是因为白天睡多了。",
    "每次照镜子我都觉得，女娲造我的时候一定是在赶工期。",
    "脸大的人一般脾气都好，因为翻脸太累了。",
    "我想在喜欢的人心里待一辈子，结果发现人家心里早就是精装修、满员入住状态了。",
    "别总嫌弃自己胖，至少你胖得很有分量，风吹不走。",
    "感情这种事，三分天注定，七分靠打拼，剩下九十分看长相。",
    "单身久了，连看两只蚂蚁并排走，都觉得它们在秀恩爱。",
    "你以为他不回你消息是在忙？其实他只是在忙着回别人的消息。",
    "喜欢的衣服买不起，喜欢的人留不住，这就是我的日常。",
    "别再问我为什么不谈恋爱了，这就好比问我为什么不买私人飞机一样。",
    "所谓真爱，就是两个人在一起互相折磨，直到谁也离不开谁。",
    "你把人家当备胎，人家可能连车都没买。",
    "有些人注定是用来错过的，比如你和你的初恋，以及你和你的存款。",
    "男人都是大猪蹄子，但你连一口猪肉都吃不上。",
    "别轻易对人掏心掏肺，因为别人可能嫌腥。",
    "真正爱你的人，不会让你一直等；一直让你等的人，只是在等比你更好的人。",
    "你的前任现在过得很好，比跟你在一起的时候好多了。",
    "为什么总有人说“颜值不重要”？因为说这话的人通常颜值都不高。",
    "岁月是把杀猪刀，但这只针对长得好看的人，对长得丑的，它毫无办法。",
    "你以为你是在享受孤独，其实你只是没人约。",
    "所谓的“顺其自然”，不过是无能为力后的自我安慰。",
    "别总说自己社恐，其实你只是对长得不好看、没钱的人社恐。",
    "职场如战场，但你连一把趁手的兵器都没有，只能当炮灰。",
    "工资就像大姨妈，一个月来一次，一周左右就没了。",
    "老板画的饼再大，也填不饱你空虚的胃。",
    "别总想着辞职去看看世界，你的存款连小区大门都出不去。",
    "所谓的“弹性工作制”，就是上班时间固定，下班时间看老板心情。",
    "每天叫醒我的不是梦想，是穷。",
    "在公司里，能者多劳，庸者多拿，而你属于“能者”里的免费劳动力。",
    "别总抱怨加班多，如果不加班，你回家又能干什么呢？",
    "年轻的时候多吃点苦，这样老了以后，你就习惯吃苦了。",
    "只要你工作够拼命，老板就能早日实现财富自由。",
    "千万不要在周末思考人生，因为周一上班时你会发现一切都是徒劳。",
    "铁饭碗的真实含义不是在一个地方吃一辈子饭，而是一辈子到哪儿都有饭吃，可惜你只有饭桶。",
    "别把同事当朋友，在利益面前，你们连塑料姐妹花都算不上。",
    "你的努力在天赋面前，简直不值一提。",
    "有些人的起点，就是你奋斗一辈子也达不到的终点。",
    "别人花钱是为了开心，我花钱是为了活着。",
    "世上本没有路，走的人多了，也就堵车了。",
    "别再说“钱乃身外之物”了，说得好像你拥有过一样。",
    "如果能用钱解决的问题，那都不是问题，问题是没钱。",
    "梦想还是要有的，万一见鬼了呢？",
    "条条大路通罗马，但有的人就生在罗马，而你生在骡马市。",
    "人生就像打电话，不是你先挂，就是我先挂。",
    "很多事情就像内裤，虽然重要，但没必要逢人就证明你有。",
    "只要我花钱的速度够快，贫穷就追不上我——结果贫穷早就把我包围了。",
    "别总觉得自己怀才不遇，也许你只是没才。",
    "生活中 99% 的烦恼都可以用钱解决，剩下的 1% 需要更多的钱。",
    "你以为你在第一层，其实你在地下室。",
    "世界上最遥远的距离，不是生与死，而是你亲手点开了付款码，却发现余额不足。",
    "别再说自己“间歇性踌躇满志，持续性混吃等死”了，你根本没有踌躇满志过。",
    "读了那么多书，依然过不好这一生，说明你书读得还不够少。",
    "优秀的人总能看到比自己更优秀的人，而平庸的人总能看到比自己更平庸的人，所以你总是很自信。",
    "别总说“我太难了”，比你难的人多的是，人家只是没空发朋友圈。",
    "有时候你不努力一下，就不知道什么叫绝望。",
    "人生没有过不去的坎，只有过不完的坎。",
    "别再给自己定什么小目标了，先定个能按时起床的目标吧。",
    "善良没用，你得漂亮，还得有钱。",
    "所有的离别都是蓄谋已久，所有的重逢都是为了再坑你一次。",
    "别把无知当个性，把没教养当直爽。",
    "你之所以觉得时间过得快，是因为你每天都在重复昨天。",
    "所谓的“佛系”，不过是既没能力争，又没胆量抢。",
    "别再幻想中彩票了，你连买彩票的钱都快掏不出来了。",
    "每个人都有自己的闪光点，而你的闪光点可能是脑门上的油光。",
    "别总嫌弃父母唠叨，等以后没人管你了，你就知道什么叫真正的孤独和贫穷了。",
    "你以为你在控制情绪，其实你只是在憋内伤。",
    "别再问“我什么时候能暴富”了，梦里什么都有，早点睡吧。",
    "真正的勇士，敢于直面惨淡的人生，敢于正视银行卡里的余额。",
    "很多事情，只要你坚持下去，就会发现，原来你真的不行。",
    "别再说“等我有钱了就……”了，你永远不会有钱的。",
    "所谓成长，就是把哭声调成静音，把银行卡密码忘掉。",
    "你以为你是主角，其实你在别人的人生里连个群演都算不上。",
    "别总觉得世界欠你一个公道，世界根本不知道你是谁。",
    "为什么总有人喜欢怀念过去？因为现在过得太惨了。",
    "别再说“我还年轻”了，同龄人孩子都打酱油了，你还在打游戏。",
    "所谓的“岁月静好”，不过是有人替你负重前行，而那个人通常不是你。",
    "别再纠结选 A 还是选 B 了，反正哪个都是错的。",
    "只要你足够平庸，就没有人能利用你。",
    "别再说“我对钱不感兴趣”了，那是马云的台词，不是你的。",
    "人生就像心电图，一帆风顺就证明你挂了。",
    "别总抱怨水逆，你人生的大部分时间都在逆水行舟，而且还没桨。",
    "真正的成熟，是看透了生活的本质后，依然选择继续当个韭菜。",
    "别再说“我要重新做人”了，上辈子你也是这么说的。",
    "你的智商就像 Wi-Fi 信号，离开路由器一米就断断续续。",
    "别总觉得别人针对你，你还没那个分量。",
    "所谓的“安全感”，就是手机满电和钱包有钱，可惜你两样都不占。",
    "别再熬夜看手机了，手机辐射不会让你变傻，但熬夜会让你变丑。",
    "每一个胖子都是潜力股，但大多数都退市了。",
    "别总说“减肥从明天开始”，你的明天已经推迟了三年了。",
    "吃得苦中苦，方为人上人——但吃苦的人太多了，人上人根本不够分。",
    "别再问“为什么受伤的总是我”了，因为你抗揍。",
    "所谓的“缘分”，就是你在等公交，而他开着宝马路过。",
    "别把别人的客气当福气，把别人的敷衍当深情。",
    "你以为你在谈恋爱，其实你在给别人做免费心理辅导。",
    "别再说“我再也不相信爱情了”，爱情从来也没相信过你。",
    "婚姻是爱情的坟墓，但没有婚姻，你的爱情只能死无葬身之地。",
    "别总嫌弃另一半这不好那不好，能看上你已经是他眼瞎了。",
    "所谓的“灵魂伴侣”，不过是两个同样无聊的人凑在一起消磨时间。",
    "别再翻前任的朋友圈了，人家早就把你屏蔽了。",
    "你之所以单身，是因为你既看不上比你差的，又配不上比你好的。",
    "别总说“男人没一个好东西”，你连坏东西都没遇到过几个。",
    "所谓的“一见钟情”，不过是见色起意；所谓的“日久生情”，不过是权衡利弊。",
    "别再等那个对的人了，他可能在来的路上迷路了，或者根本没出发。",
    "你把青春献给了工作，工作却给了你一身职业病。",
    "别总说“公司离了我转不了”，你走之后，公司转得比以前还快。",
    "所谓的“团队精神”，就是出了事大家一起背锅，拿奖金时领导独享。",
    "别再在朋友圈发加班照了，老板看不到，同事只会觉得你效率低。",
    "你的工资水平，完美匹配了你的摸鱼能力。",
    "别总想着跳槽涨薪，跳来跳去，你还是在同一个坑里。",
    "所谓的“职业规划”，就是从一个月薪三千的坑，跳到另一个月薪三千五的坑。",
    "别再抱怨领导傻逼了，能当上你领导的，再傻逼也比你强点。",
    "工作中最痛苦的事不是加班，而是加完班发现白加了。",
    "别总说“我为公司付出了多少”，公司每个月给你发的工资已经买断了你的付出。",
    "所谓的“自由职业”，就是以前只受一个老板的气，现在受无数个甲方的气。",
    "别再看那些成功学书籍了，写书的人靠卖书成功了，看书的你依然穷困潦倒。",
    "知识改变命运，但你学的都是没用的冷知识。",
    "别总说“是金子总会发光的”，你连块铁都不是，最多算块废铜烂铁。",
    "所谓的“低调”，就是你根本没有高调的资本。",
    "别再说“我不在乎别人的看法”了，那是因为根本没人在乎你。",
    "你以为你在特立独行，其实在别人眼里你就是个奇葩。",
    "别总觉得自己是个悲剧主角，悲剧至少还有观众，你连观众都没有。",
    "所谓的“断舍离”，对于穷人来说就是没钱买新的。",
    "别再说“生活不止眼前的苟且”了，还有明天的苟且和后天的苟且。",
    "你的快乐总是建立在别人的痛苦之上，可惜别人最近过得挺快乐的。",
    "别总说“如果当初……”了，就算重来一次，以你的智商还是会选错。",
    "所谓的“贵人相助”，前提是你得先是个值得帮的人，而不是扶不起的阿斗。",
    "别再抱怨社会不公平了，如果社会真的绝对公平，你连抱怨的机会都没有。",
    "那些说“平凡可贵”的人，往往自己一点都不平凡。",
    "别总说“我只是懒，真认真起来连我自己都怕”，你倒是认真一次看看啊。",
    "所谓的“慢生活”，是有钱人的专利，穷人的慢生活叫失业。",
    "别再问“人生的意义是什么”了，先想想明天的早饭钱在哪吧。",
    "你以为你在乘风破浪，其实你只是在随波逐流。",
    "别总说“爱笑的女孩运气不会太差”，运气差的女孩根本笑不出来。",
    "所谓的“内卷”，就是一群人在一个破烂的池子里互相踩踏，还以为自己在游泳。",
    "别再说“我要自律”了，你连手机都放不下。",
    "你的社交圈就像一个死水潭，除了微商就是借钱的。",
    "别总觉得自己很善良，你只是没机会作恶而已。",
    "所谓的“情商高”，很多时候就是委屈自己，成全别人。",
    "别再说“我这人比较慢热”了，你那是根本没打算热。",
    "所有的“改天再约”，翻译过来都是“再也不见”。",
    "别总把“随便”挂在嘴边，那是给有选择权的人说的，你只有“将就”。",
    "所谓的“极简主义”，就是家里穷得只剩四面墙。",
    "别再看美食视频解馋了，越看越饿，饿了又点外卖，点了又胖。",
    "你的发际线就像你的存款，每年都在以肉眼可见的速度后退。",
    "别总说“年龄只是个数字”，等你要相亲和找工作的时候，这个数字能要你的命。",
    "所谓的“青春”，就是用大把的时间去迷茫，在几个瞬间里成长，然后迅速变老。",
    "别再说“我要环游世界”了，你连自己所在的城市都没逛明白。",
    "人生就像一盒巧克力，你永远不知道下一颗有多难吃。",
    "别总觉得自己与众不同，在大数据眼里，你就是个标准的样本。",
    "所谓的“治愈系”，不过是给你打一针麻醉剂，药效过了照样疼。",
    "别再说“一切都是最好的安排”了，那只是你无力改变现状的借口。",
    "你的拖延症已经到了晚期，连“治拖延症”这件事都被你拖延了。",
    "别总说“我尽力了”，你的尽力在别人眼里只是热身。",
    "所谓的“仪式感”，就是花钱买一些平时根本用不着的垃圾。",
    "别再在深夜发矫情的朋友圈了，白天醒来删掉的时候你不觉得尴尬吗？",
    "你的存款就像冰块，放在太阳底下，眨眼就没了。",
    "别总说“等我退休了就享福了”，按现在的延迟退休政策，你能不能活到退休都是个问题。",
    "所谓的“独立女性”，就是既要像男人一样赚钱，又要像女人一样操持家务。",
    "别再说“我不在乎外貌”了，相亲第一眼看的不就是脸吗？",
    "你的脑子里装的不是智慧，是昨晚没消化的夜宵。",
    "别总说“时间会冲淡一切”，时间只会冲淡你的美貌和存款，不会冲淡你的房贷。",
    "所谓的“格局”，就是穷人用来安慰自己吃亏的借口。",
    "别再说“我还是个宝宝”了，你妈像你这么大的时候，你都上小学了。",
    "你的抗压能力就像气球，看着挺大，一戳就破。",
    "别总说“塞翁失马，焉知非福”，你丢了马之后，连马鞍都被偷了。",
    "所谓的“人脉”，就是你认识多少大佬没用，得大佬认识你才行。",
    "别再说“我要逆袭”了，小说看多了吧？现实里哪有那么多金手指。",
    "你的生活就像白开水，既没味道，还烫嘴。",
    "别总说“知足常乐”，你那不是知足，是没本事去争取更多。",
    "所谓的“安全区”，就是让你温水煮青蛙的地方。",
    "别再说“明天会更好”了，明天只是今天的复制粘贴。",
    "你的颜值就像股票，开盘即巅峰，之后一路跌停。",
    "别总说“我不怕失败”，你已经失败习惯了，当然不怕。",
    "所谓的“共情能力”，就是看别人哭自己也跟着难受，结果人家转头就去吃大餐了。",
    "别再说“我要改变世界”了，先改变一下你熬夜的习惯吧。",
    "人生没有白走的路，每一步都算数——算你倒霉。",
    "读完了这200条毒鸡汤，你是不是觉得清醒多了？清醒也没用，明天该上班还是得上班。",
]

# ===== 网络会话配置 =====
# 配置HTTP会话，优化网络请求性能
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Cache-Control': 'max-age=0'
})

# 配置连接池 - 优化网络连接性能
adapter = requests.adapters.HTTPAdapter(
    pool_connections=10,    # 连接池大小
    pool_maxsize=20,         # 最大连接数
    max_retries=3           # 最大重试次数
)
session.mount('http://', adapter)
session.mount('https://', adapter)

# ===== 缓存管理模块 =====
# 智能缓存系统，支持TTL机制和自动清理

def load_region_cache():
    """
    加载地区信息缓存
    
    从Cache.json文件中加载已缓存的IP地理位置信息，
    如果文件不存在或加载失败，则使用空缓存。
    
    Returns:
        None: 直接修改全局变量region_cache
    """
    global region_cache
    if os.path.exists('Cache.json'):
        try:
            with open('Cache.json', 'r', encoding='utf-8') as f:
                region_cache = json.load(f)
            logger.info(f"📦 成功加载缓存文件，包含 {len(region_cache)} 个条目")
        except Exception as e:
            logger.warning(f"⚠️ 加载缓存文件失败: {str(e)[:50]}")
            region_cache = {}
    else:
        logger.info("📦 缓存文件不存在，使用空缓存")
        region_cache = {}

def save_region_cache():
    """
    保存地区信息缓存
    
    将当前内存中的地区缓存数据保存到Cache.json文件中，
    用于下次启动时快速加载已查询过的IP地理位置信息。
    
    Returns:
        None: 直接保存到文件，无返回值
    """
    try:
        with open('Cache.json', 'w', encoding='utf-8') as f:
            json.dump(region_cache, f, ensure_ascii=False)
        logger.info(f"💾 成功保存缓存文件，包含 {len(region_cache)} 个条目")
    except Exception as e:
        logger.error(f"❌ 保存缓存文件失败: {str(e)[:50]}")
        pass

def is_cache_valid(timestamp, ttl_hours=24):
    """
    检查缓存是否有效
    
    Args:
        timestamp (str): 缓存时间戳（ISO格式）
        ttl_hours (int): 缓存有效期（小时），默认24小时
    
    Returns:
        bool: True表示缓存有效，False表示已过期
    """
    if not timestamp:
        return False
    cache_time = datetime.fromisoformat(timestamp)
    return datetime.now() - cache_time < timedelta(hours=ttl_hours)

def clean_expired_cache():
    """
    清理过期缓存和限制缓存大小
    
    自动清理过期的缓存条目，并限制缓存大小以防止内存溢出。
    支持TTL机制和LRU策略。
    
    Returns:
        None: 直接修改全局变量region_cache
    """
    global region_cache
    current_time = datetime.now()
    expired_keys = []
    
    # 清理过期缓存
    for ip, data in region_cache.items():
        if isinstance(data, dict) and 'timestamp' in data:
            cache_time = datetime.fromisoformat(data['timestamp'])
            if current_time - cache_time >= timedelta(hours=CONFIG["cache_ttl_hours"]):
                expired_keys.append(ip)
    
    for key in expired_keys:
        del region_cache[key]
    
    # 限制缓存大小（最多保留1000个条目）
    if len(region_cache) > 1000:
        # 按时间排序，删除最旧的条目
        sorted_items = sorted(region_cache.items(), 
                            key=lambda x: x[1].get('timestamp', '') if isinstance(x[1], dict) else '')
        items_to_remove = len(region_cache) - 1000
        for i in range(items_to_remove):
            del region_cache[sorted_items[i][0]]
        logger.info(f"缓存过大，清理了 {items_to_remove} 个旧条目")
    
    if expired_keys:
        logger.info(f"清理了 {len(expired_keys)} 个过期缓存条目")

# ===== 文件操作模块 =====
# 文件管理功能，包括删除、创建等操作

def delete_file_if_exists(file_path):
    """
    删除指定文件（如果存在）
    
    在程序开始前清理旧的结果文件，避免结果累积。
    
    Args:
        file_path (str): 要删除的文件路径
    
    Returns:
        None: 无返回值，仅执行删除操作
    """
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            logger.info(f"🗑️ 已删除原有文件: {file_path}")
        except Exception as e:
            logger.warning(f"⚠️ 删除文件失败: {str(e)}")

# ===== 网络检测模块 =====
# 网络连接测试功能，包括TCP连接、延迟测试、带宽测试等

def quick_filter_ip(ip):
    """
    快速筛选IP - 基础TCP连接测试
    
    对IP地址进行快速的TCP连接测试，快速剔除明显不可用的IP，
    这是第一轮筛选，用于减少后续深度测试的工作量。
    
    Args:
        ip (str): 要测试的IP地址
    
    Returns:
        tuple: (是否可用, 延迟毫秒数) - (bool, int)
    """
    try:
        parts = ip.split('.')
        if len(parts) != 4 or not all(0 <= int(part) <= 255 for part in parts):
            return (False, 0)
    except (ValueError, AttributeError):
        return (False, 0)
    
    min_delay = float('inf')
    success_count = 0
    
    for port in CONFIG["test_ports"]:
        try:
            if not isinstance(port, int) or not (1 <= port <= 65535):
                continue
                
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                start_time = time.time()
                
                if s.connect_ex((ip, port)) == 0:
                    delay = round((time.time() - start_time) * 1000)
                    min_delay = min(min_delay, delay)
                    success_count += 1
                    
                    if delay < 200:
                        return (True, delay)
        except (socket.timeout, socket.error, OSError):
            continue
        except Exception:
            continue
    
    if success_count > 0:
        return (True, min_delay)
    
    return (False, 0)

def test_ip_bandwidth_only(ip, current, total):
    """
    通过HTTP下载测试IP带宽性能
    
    使用真实的HTTP下载测试来测量IP的带宽性能，
    通过下载指定大小的文件来评估网络速度。
    
    Args:
        ip (str): 要测试的IP地址
        current (int): 当前测试序号
        total (int): 总测试数量
    
    Returns:
        tuple: (是否成功, 带宽Mbps, 延迟毫秒) - (bool, float, float)
    """
    try:
        # 验证IP地址格式
        parts = ip.split('.')
        if len(parts) != 4 or not all(0 <= int(part) <= 255 for part in parts):
            return (False, 0, 0)
        
        # 使用真实的下载测试来测量带宽
        test_size_bytes = CONFIG["bandwidth_test_size_mb"] * 1024 * 1024
        test_urls = [
            # 使用一些公开的测试文件
            f"https://speed.cloudflare.com/__down?bytes={test_size_bytes}",  # 可配置大小测试文件
            f"https://httpbin.org/bytes/{test_size_bytes}",  # 可配置大小测试文件
        ]
        
        best_speed = 0
        best_latency = 0
        
        # 使用配置的测试次数
        test_count = CONFIG["bandwidth_test_count"]
        for test_attempt in range(test_count):
            for url in test_urls:
                try:
                    start_time = time.time()
                    
                    # 发送HTTP请求测试带宽
                    response = session.get(
                        url, 
                        timeout=15,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                        stream=True
                    )
                    
                    if response.status_code == 200:
                        # 测量下载速度
                        data_size = 0
                        start_download = time.time()
                        
                        # 下载数据块来测试速度
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                data_size += len(chunk)
                                # 限制测试时间，避免过长时间
                                if time.time() - start_download > 10:  # 最多测试10秒
                                    break
                                # 如果下载了足够的数据就停止
                                if data_size > 10 * 1024 * 1024:  # 10MB
                                    break
                        
                        download_time = time.time() - start_download
                        latency = (start_download - start_time) * 1000  # 延迟
                        
                        if download_time > 0 and data_size > 0:
                            # 计算速度 (Mbps)
                            speed_mbps = (data_size * 8) / (download_time * 1000000)
                            best_speed = max(best_speed, speed_mbps)
                            best_latency = latency if best_latency == 0 else min(best_latency, latency)
                            
                            # 如果速度很好，可以提前返回
                            if speed_mbps > 5:  # 超过5Mbps就认为很好
                                logger.info(f"⚡ [{current}/{total}] {ip}（带宽综合速度：{best_speed:.2f}Mbps）")
                                return (True, best_speed, best_latency)
                
                except Exception as e:
                    logger.debug(f"IP {ip} 带宽测试失败: {str(e)[:50]}")
                    continue
        
        if best_speed > 0:
            logger.info(f"⚡ [{current}/{total}] {ip}（带宽综合速度：{best_speed:.2f}Mbps）")
            return (True, best_speed, best_latency)
        else:
            # 如果带宽测试失败，返回延迟测试结果
            is_available, latency = test_ip_availability(ip)
            if is_available:
                logger.info(f"⚡ [{current}/{total}] {ip}（带宽测试失败，使用延迟作为替代指标）")
                return (True, 0, latency)  # 返回0表示带宽测试失败，但延迟可用
            else:
                logger.info(f"⚡ [{current}/{total}] {ip}（带宽测试失败）")
                return (False, 0, 0)
            
    except Exception as e:
        logger.error(f"IP {ip} 带宽测试异常: {str(e)[:50]}")
        return (False, 0, 0)

def calculate_score(min_delay, avg_delay, bandwidth, stability):
    """
    计算综合评分 - 结合延迟、带宽、稳定性
    
    根据IP的延迟、带宽和稳定性等指标计算综合评分，
    用于智能排序和推荐最佳IP。
    
    Args:
        min_delay (float): 最小延迟（毫秒）
        avg_delay (float): 平均延迟（毫秒）
        bandwidth (float): 带宽（Mbps）
        stability (float): 稳定性指标
    
    Returns:
        float: 综合评分（0-100分）
    """
    # 延迟评分 (0-40分) - 延迟越低分数越高
    if min_delay <= 50:
        delay_score = 40
    elif min_delay <= 100:
        delay_score = 35
    elif min_delay <= 200:
        delay_score = 30
    elif min_delay <= 300:
        delay_score = 25
    else:
        delay_score = max(0, 20 - (min_delay - 300) / 10)
    
    # 带宽评分 (0-30分) - 带宽越高分数越高
    if bandwidth >= 50:
        bandwidth_score = 30
    elif bandwidth >= 20:
        bandwidth_score = 25
    elif bandwidth >= 10:
        bandwidth_score = 20
    elif bandwidth >= 5:
        bandwidth_score = 15
    else:
        bandwidth_score = max(0, bandwidth * 3)
    
    # 稳定性评分 (0-30分) - 稳定性越高分数越高
    stability_score = min(30, stability * 0.3)
    
    # 综合评分
    total_score = delay_score + bandwidth_score + stability_score
    
    return round(total_score, 1)

def latency_filter_ips(ip_results, percentage=30):
    """
    延迟排名筛选 - 取前N%的IP
    
    根据延迟性能对IP进行排名筛选，只保留延迟最低的前N%的IP，
    用于减少后续深度测试的工作量。
    
    Args:
        ip_results (list): IP测试结果列表
        percentage (int): 保留百分比，默认30%
    
    Returns:
        list: 筛选后的IP结果列表
    """
    if not ip_results:
        return []
    
    # 按延迟排序
    sorted_results = sorted(ip_results, key=lambda x: x[1])  # 按min_delay排序
    
    # 计算要保留的数量
    keep_count = max(1, int(len(sorted_results) * percentage / 100))
    
    # 显示筛选结果
    logger.info(f"🔍 延迟排名前{percentage}%筛选：从 {len(sorted_results)} 个IP中筛选出 {keep_count} 个IP")
    
    # 显示筛选结果
    for i, (ip, min_delay, avg_delay, stability) in enumerate(sorted_results[:keep_count], 1):
        logger.info(f"📊 {ip}（延迟排名第{i}位：{avg_delay:.1f}ms）")
    
    return sorted_results[:keep_count]

def test_ip_availability(ip):
    """
    TCP Socket检测IP可用性 - 支持多端口自定义
    
    使用TCP Socket连接测试IP的可用性和延迟，
    支持配置多个测试端口，返回最佳连接结果。
    
    Args:
        ip (str): 要测试的IP地址
    
    Returns:
        tuple: (是否可用, 延迟毫秒数) - (bool, int)
    """
    # 验证IP地址格式
    try:
        parts = ip.split('.')
        if len(parts) != 4 or not all(0 <= int(part) <= 255 for part in parts):
            return (False, 0)
    except (ValueError, AttributeError):
        return (False, 0)
    
    # 检查测试端口配置
    if not CONFIG["test_ports"] or not isinstance(CONFIG["test_ports"], list):
        logger.warning(f"⚠️ 测试端口配置无效，跳过IP {ip}")
        return (False, 0)
    
    min_delay = float('inf')
    success_count = 0
    
    # 遍历配置的测试端口
    for port in CONFIG["test_ports"]:
        try:
            # 验证端口号
            if not isinstance(port, int) or not (1 <= port <= 65535):
                logger.warning(f"⚠️ 无效端口号 {port}，跳过")
                continue
                
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)  # 3秒超时
                start_time = time.time()
                
                # 尝试TCP连接
                if s.connect_ex((ip, port)) == 0:
                    delay = round((time.time() - start_time) * 1000)
                    min_delay = min(min_delay, delay)
                    success_count += 1
                    
                    # 如果延迟很好，立即返回最佳结果
                    if delay < 200:
                        return (True, delay)
        except (socket.timeout, socket.error, OSError):
            continue  # 继续测试下一个端口
        except Exception as e:
            logger.debug(f"IP {ip} 端口 {port} 检测异常: {str(e)[:30]}")
            continue
    
    # 返回最佳结果
    if success_count > 0:
        return (True, min_delay)
    
    return (False, 0)

# ===== 地区识别模块 =====
# IP地理位置识别功能，支持多API源和智能缓存

def get_ip_region(ip):
    """
    优化的IP地区识别（支持缓存TTL）
    
    通过多个API源查询IP的地理位置信息，支持智能缓存机制，
    避免重复查询，提升查询效率。
    
    Args:
        ip (str): 要查询的IP地址
    
    Returns:
        str: 国家代码（如'US', 'CN', 'JP'等）
    """
    # 检查缓存是否有效
    if ip in region_cache:
        cached_data = region_cache[ip]
        if isinstance(cached_data, dict) and 'timestamp' in cached_data:
            if is_cache_valid(cached_data['timestamp'], CONFIG["cache_ttl_hours"]):
                logger.info(f"📦 IP {ip} 地区信息从缓存获取: {cached_data['region']}")
                return cached_data['region']
        else:
            # 兼容旧格式缓存
            logger.info(f"📦 IP {ip} 地区信息从缓存获取（旧格式）: {cached_data}")
            return cached_data
    
    # 尝试主要API（免费版本）
    logger.info(f"🌐 IP {ip} 开始API查询（主要API: ipinfo.io lite）...")
    try:
        resp = session.get(f'https://api.ipinfo.io/lite/{ip}?token=2cb674df499388', timeout=CONFIG["api_timeout"])
        if resp.status_code == 200:
            data = resp.json()
            country_code = data.get('country_code', '').upper()
            if country_code:
                region_cache[ip] = {
                    'region': country_code,
                    'timestamp': datetime.now().isoformat()
                }
                logger.info(f"✅ IP {ip} 主要API识别成功: {country_code}（来源：API查询）")
                return country_code
        else:
            logger.warning(f"⚠️ IP {ip} 主要API返回状态码: {resp.status_code}")
    except Exception as e:
        logger.error(f"❌ IP {ip} 主要API识别失败: {str(e)[:30]}")
        pass
    
    # 尝试备用API
    logger.info(f"🌐 IP {ip} 尝试备用API（ip-api.com）...")
    try:
        resp = session.get(f'http://ip-api.com/json/{ip}?fields=countryCode', timeout=CONFIG["api_timeout"])
        if resp.json().get('status') == 'success':
            country_code = resp.json().get('countryCode', '').upper()
            if country_code:
                region_cache[ip] = {
                    'region': country_code,
                    'timestamp': datetime.now().isoformat()
                }
                logger.info(f"✅ IP {ip} 备用API识别成功: {country_code}")
                return country_code
        else:
            logger.warning(f"⚠️ IP {ip} 备用API返回状态: {resp.json().get('status', 'unknown')}")
    except Exception as e:
        logger.error(f"❌ IP {ip} 备用API识别失败: {str(e)[:30]}")
        pass
    
    # 失败返回Unknown
    logger.warning(f"❌ IP {ip} 所有API识别失败，标记为Unknown")
    region_cache[ip] = {
        'region': 'Unknown',
        'timestamp': datetime.now().isoformat()
    }
    return 'Unknown'

def get_country_name(code):
    """
    根据国家代码获取中文名称
    
    将ISO国家代码转换为中文名称，用于用户友好的显示。
    
    Args:
        code (str): 国家代码（如'US', 'CN'等）
    
    Returns:
        str: 中文国家名称
    """
    return COUNTRY_MAPPING.get(code, code)

# ===== 并发处理模块 =====
# 高并发网络测试功能，支持多线程并发处理

def test_ips_concurrently(ips, max_workers=None):
    """
    超快并发检测IP可用性（防卡住优化）
    
    使用ThreadPoolExecutor实现并发处理，大幅提升检测效率。
    支持批量处理和超时保护，避免程序卡住。
    
    Args:
        ips (list): 要测试的IP地址列表
        max_workers (int): 最大并发线程数，默认使用配置值
    
    Returns:
        list: 可用IP列表，格式为[(ip, delay), ...]
    """
    if max_workers is None:
        max_workers = CONFIG["max_workers"]
    
    logger.info(f"📡 开始并发检测 {len(ips)} 个IP，使用 {max_workers} 个线程")
    available_ips = []
    
    # 使用更小的批次，避免卡住
    batch_size = CONFIG["batch_size"]  # 使用配置的批次大小
    start_time = time.time()
    
    for i in range(0, len(ips), batch_size):
        batch_ips = ips[i:i+batch_size]
        batch_num = i//batch_size + 1
        total_batches = (len(ips)-1)//batch_size + 1
        
        logger.info(f"📡 处理批次 {batch_num}/{total_batches}，包含 {len(batch_ips)} 个IP")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交批次任务，添加超时保护
            future_to_ip = {executor.submit(test_ip_availability, ip): ip for ip in batch_ips}
            
            # 处理完成的任务
            batch_completed = 0
            for future in as_completed(future_to_ip, timeout=30):  # 添加30秒超时保护
                ip = future_to_ip[future]
                batch_completed += 1
                completed = i + batch_completed
                elapsed = time.time() - start_time
                
                try:
                    is_available, delay = future.result()
                    if is_available:
                        available_ips.append((ip, delay))
                        logger.info(f"🎯 [{completed}/{len(ips)}] {ip}（TCP Ping 综合延迟：{delay:.1f}ms）")
                    else:
                        logger.info(f"[{completed}/{len(ips)}] {ip} ❌ 不可用 - 耗时: {elapsed:.1f}s")
                    
                    # 添加小延迟确保日志顺序
                    time.sleep(0.01)  # 10ms延迟
                except Exception as e:
                    logger.error(f"[{completed}/{len(ips)}] {ip} ❌ 检测出错: {str(e)[:30]} - 耗时: {elapsed:.1f}s")
                    
                    # 添加小延迟确保日志顺序
                    time.sleep(0.01)  # 10ms延迟
        
        # 批次间短暂休息，避免过度占用资源
        if i + batch_size < len(ips):
            time.sleep(0.2)  # 减少休息时间
    
    total_time = time.time() - start_time
    logger.info(f"📡 并发检测完成，发现 {len(available_ips)} 个可用IP，总耗时: {total_time:.1f}秒")
    return available_ips

def get_regions_concurrently(ips, max_workers=None):
    """
    并发识别IP地理位置，保持日志输出顺序
    
    使用多线程并发查询IP的地理位置信息，同时保持日志输出的顺序性，
    提升查询效率的同时保证用户体验。
    
    Args:
        ips (list): IP地址列表，格式为[(ip, min_delay, avg_delay), ...]
        max_workers (int): 最大并发线程数，默认使用配置值
    
    Returns:
        list: 地区识别结果，格式为[(ip, region_code, min_delay, avg_delay), ...]
    """
    if max_workers is None:
        max_workers = CONFIG["max_workers"]
    
    logger.info(f"🌍 开始并发地区识别 {len(ips)} 个IP，使用 {max_workers} 个线程")
    results = []
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_ip = {executor.submit(get_ip_region, ip): (ip, min_delay, avg_delay) for ip, min_delay, avg_delay in ips}
        
        # 先收集所有结果，不输出日志
        for i, (ip, min_delay, avg_delay) in enumerate(ips, 1):
            future = None
            # 找到对应的future
            for f, (f_ip, f_min_delay, f_avg_delay) in future_to_ip.items():
                if f_ip == ip and f_min_delay == min_delay and f_avg_delay == avg_delay:
                    future = f
                    break
            
            if future:
                try:
                    region_code = future.result()
                    results.append((ip, region_code, min_delay, avg_delay))
                    
                    # 只在API查询时等待，缓存查询不需要等待
                    if i % 10 == 0:  # 每10个IP等待一次，减少等待频率
                        time.sleep(CONFIG["query_interval"])
                except Exception as e:
                    logger.warning(f"地区识别失败 {ip}: {str(e)[:50]}")
                    results.append((ip, 'Unknown', min_delay, avg_delay))
        
        # 所有结果收集完成后，输出地区识别结果
        for i, (ip, region_code, min_delay, avg_delay) in enumerate(results, 1):
            logger.info(f"📦 [{i}/{len(ips)}] {ip} -> {region_code}")
                    
    
    total_time = time.time() - start_time
    logger.info(f"🌍 地区识别完成，处理了 {len(results)} 个IP，总耗时: {total_time:.1f}秒")
    return results


# ===== 域名解析模块（IP 唯一来源） =====
# 只解析 CONFIG["domains"] 里的三个域名：
# - 无 ECS 多源 DoH（Cloudflare/Google/doh.pub/nextdns）拿基准结果并跟 CNAME；
# - 再逐个内嵌 ECS 子网带 edns_client_subnet 向 Google DoH 查询，
#   连域名本身一起扫（有的域名带 ECS 时权威直接回该线路 A 池，只扫 CNAME 目标会漏）；
# - 只放行公网 IPv4（127.0.0.1 那类回环/私网/198.18 假 IP 直接屏蔽），不用 IPv6。
GOOGLE_DOH = "https://dns.google/resolve"
PLAIN_DOH = [
    "https://cloudflare-dns.com/dns-query",
    GOOGLE_DOH,
    "https://doh.pub/dns-query",
    "https://dns.nextdns.io/dns-query",
]
ECS_WORKERS = 24


def _doh_answers(name, base=GOOGLE_DOH, ecs=None):
    params = {"name": name, "type": "A"}
    if ecs:
        params["edns_client_subnet"] = ecs
    try:
        resp = session.get(base, params=params, headers={"accept": "application/dns-json"}, timeout=15)
        if resp.status_code != 200:
            return []
        return resp.json().get("Answer") or []
    except Exception:
        return []


def _is_public_ipv4(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.version == 4 and ip.is_global and not ip.is_multicast


def _collect_answers(answers, ips, cnames):
    for ans in answers:
        data = str(ans.get("data", "")).strip().rstrip(".")
        if ans.get("type") == 1:
            if _is_public_ipv4(data):
                ips.add(data)
        elif ans.get("type") == 5:
            cnames.add(data)


def _final_targets(domain):
    targets = {domain}
    for _ in range(8):
        nxt = set()
        for name in list(targets):
            ips, cnames = set(), set()
            for base in PLAIN_DOH:
                _collect_answers(_doh_answers(name, base), ips, cnames)
            nxt |= cnames
        if not nxt:
            break
        targets = nxt
    return targets


ECS_SUBNETS = [
    "1.1.1.0/24",
    "1.10.128.0/24",
    "5.228.0.0/24",
    "8.8.8.0/24",
    "9.9.9.0/24",
    "23.208.0.0/24",
    "24.80.0.0/24",
    "31.13.24.0/24",
    "41.205.192.0/24",
    "58.20.0.0/24",
    "58.20.64.0/24",
    "58.20.127.0/24",
    "58.20.128.0/24",
    "58.20.192.0/24",
    "58.97.0.0/24",
    "58.240.0.0/24",
    "58.240.57.0/24",
    "58.240.64.0/24",
    "58.240.128.0/24",
    "58.240.192.0/24",
    "60.191.0.0/24",
    "60.191.64.0/24",
    "60.191.128.0/24",
    "60.191.192.0/24",
    "60.217.0.0/24",
    "60.217.64.0/24",
    "60.217.128.0/24",
    "60.217.192.0/24",
    "61.8.0.0/24",
    "61.10.0.0/24",
    "61.64.127.0/24",
    "61.91.190.0/24",
    "61.95.185.0/24",
    "61.128.0.0/24",
    "61.128.64.0/24",
    "61.128.97.0/24",
    "61.128.128.0/24",
    "61.128.192.0/24",
    "61.132.163.0/24",
    "61.139.2.0/24",
    "61.144.0.0/24",
    "61.144.64.0/24",
    "61.144.128.0/24",
    "61.144.192.0/24",
    "61.157.0.0/24",
    "61.157.64.0/24",
    "61.157.128.0/24",
    "61.157.158.0/24",
    "61.157.192.0/24",
    "61.160.0.0/24",
    "61.160.64.0/24",
    "61.160.128.0/24",
    "61.160.192.0/24",
    "61.161.0.0/24",
    "61.161.64.0/24",
    "61.161.128.0/24",
    "61.161.192.0/24",
    "61.177.0.0/24",
    "61.177.64.0/24",
    "61.177.128.0/24",
    "61.177.192.0/24",
    "61.190.0.0/24",
    "61.190.64.0/24",
    "61.190.128.0/24",
    "61.190.192.0/24",
    "61.238.180.0/24",
    "62.40.34.0/24",
    "64.6.64.0/24",
    "70.24.0.0/24",
    "76.76.2.0/24",
    "81.2.69.0/24",
    "82.102.128.0/24",
    "86.98.0.0/24",
    "88.221.12.0/24",
    "89.107.129.0/24",
    "94.200.16.0/24",
    "99.224.0.0/24",
    "101.226.4.0/24",
    "103.86.96.0/24",
    "104.16.0.0/24",
    "105.224.0.0/24",
    "106.161.232.0/24",
    "109.252.114.0/24",
    "111.26.0.0/24",
    "111.26.64.0/24",
    "111.26.128.0/24",
    "111.26.192.0/24",
    "112.50.0.0/24",
    "112.50.64.0/24",
    "112.50.84.0/24",
    "112.50.128.0/24",
    "112.50.192.0/24",
    "112.96.0.0/24",
    "112.96.64.0/24",
    "112.96.128.0/24",
    "112.96.192.0/24",
    "112.122.10.0/24",
    "113.57.0.0/24",
    "113.57.249.0/24",
    "113.58.0.0/24",
    "113.59.0.0/24",
    "113.60.0.0/24",
    "113.61.0.0/24",
    "113.62.0.0/24",
    "113.64.0.0/24",
    "113.65.0.0/24",
    "114.114.114.0/24",
    "115.238.81.0/24",
    "117.102.61.0/24",
    "117.136.0.0/24",
    "117.136.6.0/24",
    "117.136.64.0/24",
    "117.136.128.0/24",
    "117.136.192.0/24",
    "117.158.0.0/24",
    "117.158.64.0/24",
    "117.158.128.0/24",
    "117.158.192.0/24",
    "117.187.0.0/24",
    "117.187.64.0/24",
    "117.187.128.0/24",
    "117.187.192.0/24",
    "119.29.29.0/24",
    "120.196.0.0/24",
    "120.196.64.0/24",
    "120.196.128.0/24",
    "120.196.165.0/24",
    "120.196.192.0/24",
    "120.208.0.0/24",
    "120.208.64.0/24",
    "120.208.128.0/24",
    "120.208.192.0/24",
    "121.88.172.0/24",
    "121.101.220.0/24",
    "123.125.0.0/24",
    "123.125.64.0/24",
    "123.125.81.0/24",
    "123.125.128.0/24",
    "123.125.192.0/24",
    "124.65.0.0/24",
    "124.65.64.0/24",
    "124.65.128.0/24",
    "124.65.192.0/24",
    "124.88.0.0/24",
    "124.88.64.0/24",
    "124.88.128.0/24",
    "124.88.192.0/24",
    "125.64.0.0/24",
    "125.64.108.0/24",
    "125.69.0.0/24",
    "125.69.40.0/24",
    "125.71.0.0/24",
    "125.76.0.0/24",
    "125.80.0.0/24",
    "125.86.0.0/24",
    "125.93.0.0/24",
    "126.0.0.0/24",
    "133.11.1.0/24",
    "139.130.4.0/24",
    "139.175.252.0/24",
    "139.192.0.0/24",
    "140.205.50.0/24",
    "142.250.0.0/24",
    "151.99.125.0/24",
    "151.232.0.0/24",
    "164.124.101.0/24",
    "166.111.8.0/24",
    "168.95.1.0/24",
    "171.208.4.0/24",
    "172.217.14.0/24",
    "177.92.0.0/24",
    "180.76.76.0/24",
    "180.101.0.0/24",
    "180.101.172.0/24",
    "180.102.0.0/24",
    "180.103.0.0/24",
    "180.104.0.0/24",
    "180.105.0.0/24",
    "180.107.0.0/24",
    "180.108.0.0/24",
    "180.110.0.0/24",
    "180.111.0.0/24",
    "180.112.0.0/24",
    "180.113.0.0/24",
    "180.114.0.0/24",
    "180.180.216.0/24",
    "180.244.71.0/24",
    "181.115.0.0/24",
    "182.138.127.0/24",
    "182.254.116.0/24",
    "183.192.0.0/24",
    "183.192.64.0/24",
    "183.192.128.0/24",
    "183.192.192.0/24",
    "183.207.0.0/24",
    "183.207.64.0/24",
    "183.207.128.0/24",
    "183.207.192.0/24",
    "183.232.0.0/24",
    "183.232.64.0/24",
    "183.232.128.0/24",
    "183.232.192.0/24",
    "185.22.153.0/24",
    "185.93.180.0/24",
    "189.38.0.0/24",
    "190.104.0.0/24",
    "193.0.14.0/24",
    "194.190.245.0/24",
    "195.54.12.0/24",
    "196.200.160.0/24",
    "197.242.0.0/24",
    "198.101.242.0/24",
    "200.160.0.0/24",
    "201.217.0.0/24",
    "202.38.64.0/24",
    "202.86.0.0/24",
    "202.86.8.0/24",
    "202.96.0.0/24",
    "202.96.64.0/24",
    "202.96.69.0/24",
    "202.96.128.0/24",
    "202.96.134.0/24",
    "202.96.199.0/24",
    "202.96.209.0/24",
    "202.97.96.0/24",
    "202.97.211.0/24",
    "202.97.224.0/24",
    "202.98.5.0/24",
    "202.98.14.0/24",
    "202.98.96.0/24",
    "202.98.160.0/24",
    "202.98.161.0/24",
    "202.98.192.0/24",
    "202.98.198.0/24",
    "202.98.224.0/24",
    "202.99.96.0/24",
    "202.99.160.0/24",
    "202.99.192.0/24",
    "202.99.224.0/24",
    "202.100.0.0/24",
    "202.100.4.0/24",
    "202.100.72.0/24",
    "202.100.96.0/24",
    "202.100.128.0/24",
    "202.100.192.0/24",
    "202.101.98.0/24",
    "202.101.172.0/24",
    "202.101.224.0/24",
    "202.101.226.0/24",
    "202.102.3.0/24",
    "202.102.24.0/24",
    "202.102.128.0/24",
    "202.102.152.0/24",
    "202.102.192.0/24",
    "202.102.224.0/24",
    "202.102.227.0/24",
    "202.103.0.0/24",
    "202.103.24.0/24",
    "202.103.96.0/24",
    "202.103.224.0/24",
    "202.104.96.0/24",
    "202.105.0.0/24",
    "202.106.0.0/24",
    "202.106.64.0/24",
    "202.106.128.0/24",
    "202.106.192.0/24",
    "202.129.206.0/24",
    "202.138.96.0/24",
    "202.175.0.0/24",
    "203.50.2.0/24",
    "203.80.96.0/24",
    "203.98.7.0/24",
    "203.104.64.0/24",
    "203.113.172.0/24",
    "203.124.230.0/24",
    "203.144.207.0/24",
    "203.186.94.0/24",
    "203.226.206.0/24",
    "203.248.252.0/24",
    "208.67.222.0/24",
    "210.0.255.0/24",
    "210.21.0.0/24",
    "210.21.64.0/24",
    "210.21.128.0/24",
    "210.21.192.0/24",
    "210.21.196.0/24",
    "210.22.70.0/24",
    "210.82.0.0/24",
    "210.82.64.0/24",
    "210.82.128.0/24",
    "210.82.192.0/24",
    "210.185.0.0/24",
    "210.196.3.0/24",
    "210.209.120.0/24",
    "210.220.163.0/24",
    "211.136.0.0/24",
    "211.136.32.0/24",
    "211.136.64.0/24",
    "211.136.96.0/24",
    "211.136.128.0/24",
    "211.136.160.0/24",
    "211.136.192.0/24",
    "211.136.224.0/24",
    "211.137.0.0/24",
    "211.137.32.0/24",
    "211.137.64.0/24",
    "211.137.96.0/24",
    "211.137.128.0/24",
    "211.137.160.0/24",
    "211.137.192.0/24",
    "211.137.224.0/24",
    "211.138.0.0/24",
    "211.138.32.0/24",
    "211.138.64.0/24",
    "211.138.96.0/24",
    "211.138.128.0/24",
    "211.138.160.0/24",
    "211.138.180.0/24",
    "211.138.192.0/24",
    "211.138.224.0/24",
    "211.138.245.0/24",
    "211.139.0.0/24",
    "211.139.32.0/24",
    "211.139.64.0/24",
    "211.139.96.0/24",
    "211.139.128.0/24",
    "211.139.160.0/24",
    "211.139.192.0/24",
    "211.139.224.0/24",
    "217.169.20.0/24",
    "218.30.0.0/24",
    "218.30.118.0/24",
    "218.31.0.0/24",
    "218.75.0.0/24",
    "218.75.121.0/24",
    "218.76.0.0/24",
    "218.77.0.0/24",
    "218.104.0.0/24",
    "218.104.47.0/24",
    "218.104.64.0/24",
    "218.104.111.0/24",
    "218.104.128.0/24",
    "218.104.192.0/24",
    "218.201.96.0/24",
    "218.206.0.0/24",
    "219.72.0.0/24",
    "219.128.0.0/24",
    "219.137.0.0/24",
    "219.141.0.0/24",
    "219.141.136.0/24",
    "219.144.0.0/24",
    "219.148.0.0/24",
    "219.148.204.0/24",
    "219.150.0.0/24",
    "219.152.0.0/24",
    "219.158.0.0/24",
    "220.162.0.0/24",
    "220.162.96.0/24",
    "220.165.0.0/24",
    "220.168.0.0/24",
    "220.170.0.0/24",
    "220.172.0.0/24",
    "220.175.0.0/24",
    "220.178.0.0/24",
    "220.181.0.0/24",
    "221.5.0.0/24",
    "221.5.64.0/24",
    "221.5.88.0/24",
    "221.5.128.0/24",
    "221.5.192.0/24",
    "221.7.0.0/24",
    "221.7.64.0/24",
    "221.7.92.0/24",
    "221.7.128.0/24",
    "221.7.192.0/24",
    "221.11.0.0/24",
    "221.11.1.0/24",
    "221.11.64.0/24",
    "221.11.128.0/24",
    "221.11.192.0/24",
    "221.130.33.0/24",
    "222.85.0.0/24",
    "222.85.64.0/24",
    "222.88.0.0/24",
    "222.160.0.0/24",
    "222.161.0.0/24",
    "222.168.0.0/24",
    "222.169.0.0/24",
    "222.172.0.0/24",
    "222.172.200.0/24",
    "222.175.0.0/24",
    "222.209.0.0/24",
    "222.216.0.0/24",
    "222.218.0.0/24",
    "222.221.0.0/24",
    "222.240.0.0/24",
    "222.246.0.0/24",
    "222.246.129.0/24",
    "222.247.0.0/24",
    "222.248.0.0/24",
    "223.5.5.0/24",
    "223.81.0.0/24",
    "223.81.64.0/24",
    "223.81.128.0/24",
    "223.81.192.0/24",
    "223.104.0.0/24",
    "223.104.64.0/24",
    "223.104.128.0/24",
    "223.104.192.0/24",
    "223.104.255.0/24",
]


def _load_ecs_subnets():
    # ECS 地域子网清单已内嵌，不需要任何外部文件
    return list(ECS_SUBNETS)


def resolve_domain_ips(domain, ecs_list):
    """全量解析一个域名在各线路的 IPv4，返回 IP 集合。"""
    ips, cnames = set(), set()
    targets = _final_targets(domain)
    names = {domain} | targets
    for name in names:
        for base in PLAIN_DOH:
            _collect_answers(_doh_answers(name, base), ips, cnames)

    def one(ecs):
        got, junk = set(), set()
        for name in names:
            _collect_answers(_doh_answers(name, GOOGLE_DOH, ecs), got, junk)
        return got

    if ecs_list:
        with ThreadPoolExecutor(max_workers=ECS_WORKERS) as ex:
            for got in ex.map(one, ecs_list):
                ips |= got
    return ips


# ===== 主程序模块 =====
# 程序主流程控制，协调各个模块完成IP采集、检测、排序和输出

def main():
    """
    主程序入口
    
    执行完整的IP采集、检测、排序和输出流程：
    1. 采集IP地址
    2. 快速筛选
    3. 地区识别
    4. 深度测试（高级模式）
    5. 结果输出
    
    Returns:
        None: 程序执行完成后退出
    """
    start_time = time.time()
    
    # 1. 预处理：删除旧文件
    # 清理之前运行生成的结果文件，避免结果累积
    delete_file_if_exists('IPlist.txt')
    delete_file_if_exists('Senflare.txt')
    if CONFIG["advanced_mode"]:
        delete_file_if_exists('IPlist-Pro.txt')
        delete_file_if_exists('Senflare-Pro.txt')
        delete_file_if_exists('Ranking.txt')
    logger.info("🗑️ 预处理完成，旧文件已清理")

    # 2. 采集IP地址
    # 从多个API源并发采集IP地址，获取大量候选IP
    logger.info("📥 ===== 采集IP地址 =====")
    all_ips = []
    successful_sources = 0
    failed_sources = 0
    
    # 解析 CONFIG["domains"] 里的三个域名（唯一 IP 来源）
    ecs_list = _load_ecs_subnets()
    logger.info(f"🌐 ECS 地域子网 {len(ecs_list)} 个，开始全量解析 {len(CONFIG['domains'])} 个域名")
    for domain in CONFIG["domains"]:
        try:
            logger.info(f"🔍 解析 {domain} ...")
            domain_ips = resolve_domain_ips(domain, ecs_list)
            all_ips.extend(sorted(domain_ips))
            successful_sources += 1
            logger.info(f"✅ {domain} 解析到 {len(domain_ips)} 个 IP")
        except Exception as e:
            failed_sources += 1
            logger.error(f"❌ {domain} 解析出错: {str(e)[:50]}")
    logger.info(f"📊 采集统计: 成功 {successful_sources} 个域名，失败 {failed_sources} 个域名")

    # 3. IP去重与排序
    # 对采集到的IP进行去重和排序，确保唯一性
    unique_ips = sorted(list(set(all_ips)), key=lambda x: [int(p) for p in x.split('.')])
    logger.info(f"🔢 去重后共 {len(unique_ips)} 个唯一IP地址")
    # 总量上限 100 个（定死）：不管以后加多少个域名，全部域名解出的 IP 合并去重后最多留 100 个
    if len(unique_ips) > 100:
        unique_ips = unique_ips[:100]
        logger.info("✂️ 已截断为 100 个（总量上限）")
    
    # 检查是否有IP需要检测
    if not unique_ips:
        logger.warning("⚠️ 没有采集到任何IP地址，程序结束")
        return

    # 4. 快速筛选
    # 使用TCP连接测试快速剔除明显不可用的IP，减少后续测试工作量
    logger.info("🔍 ===== 快速筛选 =====")
    filtered_ips = []
    for ip in unique_ips:
        is_good, delay = quick_filter_ip(ip)
        if is_good:
            filtered_ips.append(ip)
            logger.info(f"✅ 可用 {ip}（延迟 {delay}ms）")
        else:
            logger.info(f"❌ {ip} 被快速筛选剔除")
    
    logger.info(f"🔍 快速筛选完成，保留 {len(filtered_ips)} 个IP")
    
    if not filtered_ips:
        logger.warning("⚠️ 快速筛选后无可用IP，程序结束")
        return

    # 5. 立即保存基础文件（快速筛选完成后）
    # 保存基础版IP列表，供用户快速使用
    logger.info("📄 ===== 保存基础文件 =====")
    with open('IPlist.txt', 'w', encoding='utf-8') as f:
        for ip in filtered_ips:
            f.write(f"{ip}\n")
    logger.info(f"📄 已保存 {len(filtered_ips)} 个可用IP到 IPlist.txt")
    
    # 6. 立即进行地区识别与结果格式化（提前保存Senflare.txt）
    # 对快速筛选的IP进行地区识别，生成格式化结果
    logger.info("🌍 ===== 并发地区识别与结果格式化 =====")
    # 使用快速筛选的IP进行地区识别
    ip_delay_data = [(ip, 0, 0) for ip in filtered_ips]  # 使用快速筛选的IP，延迟设为0
    
    region_results = get_regions_concurrently(ip_delay_data)
    
    # 按地区分组
    region_groups = defaultdict(list)
    for ip, region_code, min_delay, avg_delay in region_results:
        country_name = get_country_name(region_code)
        region_groups[country_name].append((ip, region_code, min_delay, avg_delay))
    
    logger.info(f"🌍 地区分组完成，共 {len(region_groups)} 个地区")
    
    # 生成并保存最终结果
    result_ips = []
    for region in sorted(region_groups.keys()):
        # 同一地区内按延迟排序（更快的在前）
        sorted_ips = sorted(region_groups[region], key=lambda x: x[2])  # 按min_delay排序
        for idx, (ip, code, min_delay, avg_delay) in enumerate(sorted_ips, 1):
            result_ips.append(ip)
        logger.debug(f"地区 {region} 格式化完成，包含 {len(sorted_ips)} 个IP")
    
    result_ips = result_ips[:100]  # 基础版上限 100 条（定死）
    # 毒鸡汤固定分配：第 N 个 IP 配第 N 句，更新时只换 IP、文字不动
    entry_by_ip = {ip: FIXED_NODE_NAMES[i] for i, ip in enumerate(result_ips)}
    result = [f"{ip}# {entry_by_ip[ip]}" for ip in result_ips]
    if result:
        # 立即保存基础文件
        with open('Senflare.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(result))
        logger.info(f"📄 已保存 {len(result)} 条格式化记录到 Senflare.txt")
    else:
        logger.warning("⚠️ 无有效记录可保存")

    # 7. 延迟排名前30%筛选（基于快速筛选结果）
    # 根据延迟性能筛选出前30%的IP，用于后续深度测试
    logger.info("🔍 ===== 延迟排名前30%筛选 =====")
    # 对快速筛选的IP进行延迟排名筛选，使用快速筛选的实际延迟数据
    quick_filter_results = []
    for ip in filtered_ips:
        # 重新获取快速筛选的延迟数据
        is_good, delay = quick_filter_ip(ip)
        if is_good:
            quick_filter_results.append((ip, delay, delay, 0))  # (ip, min_delay, avg_delay, stability)
    
    latency_filtered_ips = latency_filter_ips(quick_filter_results, CONFIG["latency_filter_percentage"])
    logger.info(f"🔍 延迟筛选完成，保留 {len(latency_filtered_ips)} 个IP")

    # 8. TCP Ping测试（只测试延迟，不测试带宽）
    # 对筛选后的IP进行精确的TCP延迟测试
    logger.info("🔍 ===== TCP Ping测试 =====")
    tcp_ping_ips = test_ips_concurrently([ip for ip, _, _, _ in latency_filtered_ips])

    # 9. 带宽测试（只对筛选后的IP进行带宽测试）
    # 对通过延迟筛选的IP进行HTTP带宽测试，评估网络性能
    logger.info("🔍 ===== 带宽测试 =====")
    # 进行带宽测试
    bandwidth_results = []
    for i, (ip, delay) in enumerate(tcp_ping_ips, 1):
        is_fast, bandwidth, latency = test_ip_bandwidth_only(ip, i, len(tcp_ping_ips))
        if is_fast:
            # 使用TCP Ping测试的延迟数据
            min_delay = delay
            avg_delay = delay
            stability = 100  # 默认稳定性
            score = calculate_score(min_delay, avg_delay, bandwidth, stability)
            bandwidth_results.append((ip, min_delay, avg_delay, bandwidth, latency, score))
    available_ips = bandwidth_results

    # 8. 保存高级文件（按评分排序）
    # 生成高级版IP列表和详细排名信息
    if available_ips:
        # 按评分排序（如果测试了带宽）
        if len(available_ips[0]) > 5:
            available_ips.sort(key=lambda x: x[5], reverse=True)  # 按评分排序
        logger.info(f"📊 按综合评分排序完成")
        
        # 保存高级文件（高级选项）
        # 保存优选IP列表
        with open('IPlist-Pro.txt', 'w', encoding='utf-8') as f:
            for ip, min_delay, avg_delay, bandwidth, latency, score in available_ips:
                f.write(f"{ip}\n")
        logger.info(f"📄 已保存 {len(available_ips)} 个优选IP到 IPlist-Pro.txt")
        
        # 保存详细排名信息
        with open('Ranking.txt', 'w', encoding='utf-8') as f:
            for i, (ip, min_delay, avg_delay, bandwidth, latency, score) in enumerate(available_ips, 1):
                f.write(f"📊 [{i}/{len(available_ips)}] {ip}（延迟 {min_delay}ms，带宽 {bandwidth:.2f}Mbps，评分 {score:.1f}）\n")
        logger.info(f"📄 已保存排名详情到 Ranking.txt")
        
        # 保存高级格式化文件（使用优选IP重新生成）
        # 对优选IP进行地区识别，生成高级版格式化结果
        logger.info("🌍 ===== 高级地区识别与结果格式化 =====")
        # 使用优选IP进行地区识别
        pro_ip_delay_data = [(ip, 0, 0) for ip, _, _, _, _, _ in available_ips]
        pro_region_results = get_regions_concurrently(pro_ip_delay_data)
        
        # 按地区分组
        pro_region_groups = defaultdict(list)
        for ip, region_code, min_delay, avg_delay in pro_region_results:
            country_name = get_country_name(region_code)
            pro_region_groups[country_name].append((ip, region_code, min_delay, avg_delay))
        
        logger.info(f"🌍 高级地区分组完成，共 {len(pro_region_groups)} 个地区")
        
        # 生成高级格式化结果（同一个 IP 沿用基础版那句毒鸡汤）
        pro_result_ips = []
        for region in sorted(pro_region_groups.keys()):
            # 同一地区内按延迟排序（更快的在前）
            sorted_ips = sorted(pro_region_groups[region], key=lambda x: x[2])  # 按min_delay排序
            for idx, (ip, code, min_delay, avg_delay) in enumerate(sorted_ips, 1):
                pro_result_ips.append(ip)
            logger.debug(f"高级地区 {region} 格式化完成，包含 {len(sorted_ips)} 个IP")
        
        pro_result_ips = pro_result_ips[:100]  # 高级版上限 100 条（定死）
        pro_result = [f"{ip}# {entry_by_ip.get(ip, FIXED_NODE_NAMES[i])}" for i, ip in enumerate(pro_result_ips)]
        if pro_result:
            with open('Senflare-Pro.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(pro_result))
            logger.info(f"📄 已保存 {len(pro_result)} 条高级格式化记录到 Senflare-Pro.txt")
        else:
            logger.warning("⚠️ 高级版无有效记录可保存")
    else:
        logger.warning("⚠️ 高级版无有效记录可保存")

    # 9. 保存缓存并显示统计信息
    # 保存地区缓存，显示运行统计信息
    save_region_cache()
    
    # 显示总耗时
    run_time = round(time.time() - start_time, 2)
    logger.info(f"⏱️ 总耗时: {run_time}秒")
    logger.info(f"📊 缓存统计: 总计 {len(region_cache)} 个")
    logger.info("🏁 ===== 程序完成 =====")

# ===== 程序入口 =====
# 程序启动入口，初始化缓存并执行主程序

if __name__ == "__main__":
    """
    程序启动入口
    
    初始化缓存系统，执行主程序流程，处理异常情况。
    支持用户中断和异常处理。
    """
    # 程序启动日志
    logger.info("🚀 ===== 开始IP处理程序 =====")
    
    # 初始化缓存系统
    load_region_cache()
    
    # 清理过期缓存条目
    clean_expired_cache()
    
    # 执行主程序流程
    try:
        main()
    except KeyboardInterrupt:
        logger.info("⏹️ 程序被用户中断")
    except Exception as e:
        logger.error(f"❌ 程序运行出错: {str(e)}")
