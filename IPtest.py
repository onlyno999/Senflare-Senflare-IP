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


# ===== 三字经节点名（固定 100 条） =====
# 节点显示名固定使用《三字经》前 100 句（每句附一句白话解释），顺序写死：
# 第 N 个 IP 永远配第 N 句，以后更新只换 IP、文字不动。
# 同一个 IP 在基础版和高级版中使用同一句（按基础版顺序分配）。
SANZIJING_ENTRIES = [
    "人之初|性本善 - 人在刚出生的时候，天性本来都是善良的。",
    "性相近|习相远 - 人的本性原本相近，只是后天习染使人相差越来越远。",
    "苟不教|性乃迁 - 如果不去教育，善良的本性就会随着环境改变。",
    "教之道|贵以专 - 教育的方法，最重要的是专心一致、持之以恒。",
    "昔孟母|择邻处 - 从前孟子的母亲，为了给孩子选个好环境而多次搬家。",
    "子不学|断机杼 - 孟子逃学回家，孟母剪断织布机上的布来教育他。",
    "窦燕山|有义方 - 五代时窦燕山，教育孩子有很好的方法。",
    "教五子|名俱扬 - 他教出的五个儿子都考中进士，声名远扬。",
    "养不教|父之过 - 只养孩子而不教育，是做父亲的过错。",
    "教不严|师之惰 - 只教书而要求不严格，是做老师的懒惰。",
    "子不学|非所宜 - 小孩子不好好学习，是不应该的。",
    "幼不学|老何为 - 小时候不学习，长大了还能有什么作为呢。",
    "玉不琢|不成器 - 玉石不经过打磨，就成不了精美的器物。",
    "人不学|不知义 - 人不经过学习，就不会懂得做人的道理。",
    "为人子|方少时 - 做儿女的，在年少的时候。",
    "亲师友|习礼仪 - 就要亲近老师和朋友，学习待人接物的礼仪。",
    "香九龄|能温席 - 黄香九岁时，就懂得给父亲暖被窝。",
    "孝于亲|所当执 - 孝顺父母，是每个子女都应当做到的。",
    "融四岁|能让梨 - 孔融四岁时，就知道把大梨让给哥哥吃。",
    "弟于长|宜先知 - 做弟弟的尊敬兄长，这是首先要懂得的道理。",
    "首孝弟|次见闻 - 首先要学会孝顺父母、友爱兄弟，其次才是增长见闻。",
    "知某数|识某文 - 要知道基本的算数，认识文字学问。",
    "一而十|十而百 - 一到十，十到百，这是十进制的计数方法。",
    "百而千|千而万 - 百到千，千到万，数目就这样不断增大。",
    "三才者|天地人 - 所谓三才，指的是天、地、人三者。",
    "三光者|日月星 - 所谓三光，指的是太阳、月亮和星星。",
    "三纲者|君臣义 - 所谓三纲，君臣之间要讲道义。",
    "父子亲|夫妇顺 - 父子之间要亲爱，夫妇之间要和顺。",
    "曰春夏|曰秋冬 - 一年有春、夏、秋、冬四个季节。",
    "此四时|运不穷 - 四季循环交替，运行永无穷尽。",
    "曰南北|曰西东 - 有南、北、西、东四个方向。",
    "此四方|应乎中 - 这四个方向，都对应着中央的位置。",
    "曰水火|木金土 - 水、火、木、金、土，合称五行。",
    "此五行|本乎数 - 五行相生相克，源于天地运行的规律。",
    "曰仁义|礼智信 - 仁、义、礼、智、信，是做人的五种常德。",
    "此五常|不容紊 - 这五常之道，不容许紊乱废弃。",
    "稻粱菽|麦黍稷 - 稻、粱、菽、麦、黍、稷，是人们常吃的粮食。",
    "此六谷|人所食 - 这六种谷物，是人类赖以生存的主食。",
    "马牛羊|鸡犬豕 - 马、牛、羊、鸡、狗、猪，是常见的家畜家禽。",
    "此六畜|人所饲 - 这六种牲畜，都是人们饲养的。",
    "曰喜怒|曰哀惧 - 喜、怒、哀、惧，是人天生的情绪。",
    "爱恶欲|七情具 - 再加上爱、恶、欲，人就具备了七情。",
    "匏土革|木石金 - 匏、土、革、木、石、金，是制作乐器的材料。",
    "与丝竹|乃八音 - 再加上丝和竹，合称为八音。",
    "高曾祖|父而身 - 由高祖、曾祖、祖父、父亲，传到自己这一身。",
    "身而子|子而孙 - 自己再传给儿子，儿子再传给孙子。",
    "自子孙|至玄曾 - 从子孙辈一直数到玄孙、曾孙辈。",
    "乃九族|人之伦 - 这九代人合称九族，是人伦关系的次序。",
    "父子恩|夫妇从 - 父子之间要有恩情，夫妇之间要和顺相从。",
    "兄则友|弟则恭 - 兄长要友爱弟弟，弟弟要恭敬兄长。",
    "长幼序|友与朋 - 长辈幼辈要有次序，朋友之间要诚信来往。",
    "君则敬|臣则忠 - 君主要尊重臣下，臣下要忠于君主。",
    "此十义|人所同 - 这十种人伦之道，是所有人共同遵守的。",
    "当师叙|勿违背 - 应当听从老师的教导讲解，不要违背。",
    "斩齐衰|大小功 - 斩衰、齐衰、大功，是古代丧服的等级。",
    "至缌麻|五服终 - 再到小功、缌麻，五服的制度就齐全了。",
    "礼乐射|御书数 - 礼、乐、射、御、书、数，是古人学习的六种技艺。",
    "古六艺|今不具 - 古代的六艺，到如今已经不完备了。",
    "惟书学|人共遵 - 只有文字之学，是大家共同遵循学习的。",
    "既识字|讲说文 - 认识了字，就要讲解《说文解字》来明字义。",
    "有古文|大小篆 - 字体有古文、大篆和小篆。",
    "隶草继|不可乱 - 后来又有隶书和草书，演变的次序不可混淆。",
    "若广学|惧其繁 - 如果要广泛地学，恐怕内容太繁杂。",
    "但略说|能知原 - 这里只大略地说一说，让人知道个源头。",
    "凡训蒙|须讲究 - 凡是教育小孩子，必须讲究方法。",
    "详训诂|明句读 - 要详细讲解字义，清楚地断句标点。",
    "为学者|必有初 - 做学问的人，必须有个良好的开端。",
    "小学终|至四书 - 小学学完了，就可以进而学习四书。",
    "论语者|二十篇 - 《论语》一书共有二十篇。",
    "群弟子|记善言 - 是孔子的弟子们记录下的老师的嘉言。",
    "孟子者|七篇止 - 《孟子》一书共有七篇。",
    "讲道德|说仁义 - 讲的是道德学问，说的是仁义之道。",
    "作中庸|子思笔 - 《中庸》是子思的著作。",
    "中不偏|庸不易 - “中”是不偏不倚，“庸”是永远不变的常理。",
    "作大学|乃曾子 - 《大学》是曾子的著作。",
    "自修齐|至平治 - 从修身、齐家做起，到治国、平天下。",
    "孝经通|四书熟 - 《孝经》读通了，四书读熟了。",
    "如六经|始可读 - 就可以开始研读六经了。",
    "诗书易|礼春秋 - 《诗》《书》《易》《礼》《春秋》。",
    "号六经|当讲求 - 合称为六经，应当认真钻研。",
    "有连山|有归藏 - 易学有《连山》《归藏》两部。",
    "有周易|三易详 - 再加上《周易》，三易的内容就详细了。",
    "有典谟|有训诰 - 《尚书》里有典、谟、训、诰等体裁。",
    "有誓命|书之奥 - 还有誓和命，这些都是《尚书》的精深之处。",
    "我周公|作周礼 - 我们的周公，制作了《周礼》。",
    "著六官|存治体 - 设立六官的制度，保存了治国的体制。",
    "大小戴|注礼记 - 大戴和小戴，注释整理了《礼记》。",
    "述圣言|礼乐备 - 记述圣人的言论，使礼乐制度完备。",
    "曰国风|曰雅颂 - 《诗经》有国风、大雅、小雅和颂。",
    "号四诗|当讽咏 - 合称四诗，应当吟咏诵读。",
    "诗既亡|春秋作 - 采诗的制度废止后，孔子便编写了《春秋》。",
    "寓褒贬|别善恶 - 其中寄托着褒贬之意，用来分辨善恶。",
    "三传者|有公羊 - 解释《春秋》的三传，有《公羊传》。",
    "有左氏|有谷梁 - 还有《左氏传》和《谷梁传》。",
    "经既明|方读子 - 经书通晓之后，才可以读诸子百家的书。",
    "撮其要|记其事 - 要摘取其中的要点，记住重要的事实。",
    "五子者|有荀扬 - 五位重要的子家人物，有荀子和扬子。",
    "文中子|及老庄 - 还有文中子，以及老子和庄子。",
    "经子通|读诸史 - 经书和子书都通晓了，就可以读各种史书。",
    "考世系|知终始 - 考察历代的世系传承，知道历史的始末。",
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
    # 三字经固定分配：第 N 个 IP 配第 N 句，更新时只换 IP、文字不动
    entry_by_ip = {ip: SANZIJING_ENTRIES[i] for i, ip in enumerate(result_ips)}
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
        
        # 生成高级格式化结果（同一个 IP 沿用基础版那句三字经）
        pro_result_ips = []
        for region in sorted(pro_region_groups.keys()):
            # 同一地区内按延迟排序（更快的在前）
            sorted_ips = sorted(pro_region_groups[region], key=lambda x: x[2])  # 按min_delay排序
            for idx, (ip, code, min_delay, avg_delay) in enumerate(sorted_ips, 1):
                pro_result_ips.append(ip)
            logger.debug(f"高级地区 {region} 格式化完成，包含 {len(sorted_ips)} 个IP")
        
        pro_result_ips = pro_result_ips[:100]  # 高级版上限 100 条（定死）
        pro_result = [f"{ip}# {entry_by_ip.get(ip, SANZIJING_ENTRIES[i])}" for i, ip in enumerate(pro_result_ips)]
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
