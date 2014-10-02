# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# TODO
# - factorize default TCP/UDP ports
# - have different severity per port?

import re
import collections
import netaddr
import socket
import os
import uuid

from urlparse import urlparse
from minion.plugins.base import ExternalProcessPlugin

default_tcp_ports = '1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,709,711,714,720,722,726,730,731,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2998,3000,3001,3003,3005,3006,3011,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389'
default_udp_ports = 'U:2,U:3,U:7,U:9,U:13,U:17,U:19,U:20,U:21,U:22,U:23,U:37,U:38,U:42,U:49,U:53,U:67,U:68,U:69,U:80,U:88,U:111,U:112,U:113,U:120,U:123,U:135,U:136,U:137,U:138,U:139,U:158,U:161,U:162,U:177,U:192,U:199,U:207,U:217,U:363,U:389,U:402,U:407,U:427,U:434,U:443,U:445,U:464,U:497,U:500,U:502,U:512,U:513,U:514,U:515,U:517,U:518,U:520,U:539,U:559,U:593,U:623,U:626,U:631,U:639,U:643,U:657,U:664,U:682,U:683,U:684,U:685,U:686,U:687,U:688,U:689,U:764,U:767,U:772,U:773,U:774,U:775,U:776,U:780,U:781,U:782,U:786,U:789,U:800,U:814,U:826,U:829,U:838,U:902,U:903,U:944,U:959,U:965,U:983,U:989,U:990,U:996,U:997,U:998,U:999,U:1000,U:1001,U:1007,U:1008,U:1012,U:1013,U:1014,U:1019,U:1020,U:1021,U:1022,U:1023,U:1024,U:1025,U:1026,U:1027,U:1028,U:1029,U:1030,U:1031,U:1032,U:1033,U:1034,U:1035,U:1036,U:1037,U:1038,U:1039,U:1040,U:1041,U:1042,U:1043,U:1044,U:1045,U:1046,U:1047,U:1048,U:1049,U:1050,U:1051,U:1053,U:1054,U:1055,U:1056,U:1057,U:1058,U:1059,U:1060,U:1064,U:1065,U:1066,U:1067,U:1068,U:1069,U:1070,U:1072,U:1080,U:1081,U:1087,U:1088,U:1090,U:1100,U:1101,U:1105,U:1124,U:1200,U:1214,U:1234,U:1346,U:1419,U:1433,U:1434,U:1455,U:1457,U:1484,U:1485,U:1524,U:1645,U:1646,U:1701,U:1718,U:1719,U:1761,U:1782,U:1804,U:1812,U:1813,U:1885,U:1886,U:1900,U:1901,U:1993,U:2000,U:2002,U:2048,U:2049,U:2051,U:2148,U:2160,U:2161,U:2222,U:2223,U:2343,U:2345,U:2362,U:2967,U:3052,U:3130,U:3283,U:3296,U:3343,U:3389,U:3401,U:3456,U:3457,U:3659,U:3664,U:3702,U:3703,U:4000,U:4008,U:4045,U:4444,U:4500,U:4666,U:4672,U:5000,U:5001,U:5002,U:5003,U:5010,U:5050,U:5060,U:5093,U:5351,U:5353,U:5355,U:5500,U:5555,U:5632,U:6000,U:6001,U:6002,U:6004,U:6050,U:6346,U:6347,U:6970,U:6971,U:7000,U:7938,U:8000,U:8001,U:8010,U:8181,U:8193,U:8900,U:9000,U:9001,U:9020,U:9103,U:9199,U:9200,U:9370,U:9876,U:9877,U:9950,U:10000,U:10080,U:11487,U:16086,U:16402,U:16420,U:16430,U:16433,U:16449,U:16498,U:16503,U:16545,U:16548,U:16573,U:16674,U:16680,U:16697,U:16700,U:16708,U:16711,U:16739,U:16766,U:16779,U:16786,U:16816,U:16829,U:16832,U:16838,U:16839,U:16862,U:16896,U:16912,U:16918,U:16919,U:16938,U:16939,U:16947,U:16948,U:16970,U:16972,U:16974,U:17006,U:17018,U:17077,U:17091,U:17101,U:17146,U:17184,U:17185,U:17205,U:17207,U:17219,U:17236,U:17237,U:17282,U:17302,U:17321,U:17331,U:17332,U:17338,U:17359,U:17417,U:17423,U:17424,U:17455,U:17459,U:17468,U:17487,U:17490,U:17494,U:17505,U:17533,U:17549,U:17573,U:17580,U:17585,U:17592,U:17605,U:17615,U:17616,U:17629,U:17638,U:17663,U:17673,U:17674,U:17683,U:17726,U:17754,U:17762,U:17787,U:17814,U:17823,U:17824,U:17836,U:17845,U:17888,U:17939,U:17946,U:17989,U:18004,U:18081,U:18113,U:18134,U:18156,U:18228,U:18234,U:18250,U:18255,U:18258,U:18319,U:18331,U:18360,U:18373,U:18449,U:18485,U:18543,U:18582,U:18605,U:18617,U:18666,U:18669,U:18676,U:18683,U:18807,U:18818,U:18821,U:18830,U:18832,U:18835,U:18869,U:18883,U:18888,U:18958,U:18980,U:18985,U:18987,U:18991,U:18994,U:18996,U:19017,U:19022,U:19039,U:19047,U:19075,U:19096,U:19120,U:19130,U:19140,U:19141,U:19154,U:19161,U:19165,U:19181,U:19193,U:19197,U:19222,U:19227,U:19273,U:19283,U:19294,U:19315,U:19322,U:19332,U:19374,U:19415,U:19482,U:19489,U:19500,U:19503,U:19504,U:19541,U:19600,U:19605,U:19616,U:19624,U:19625,U:19632,U:19639,U:19647,U:19650,U:19660,U:19662,U:19663,U:19682,U:19683,U:19687,U:19695,U:19707,U:19717,U:19718,U:19719,U:19722,U:19728,U:19789,U:19792,U:19933,U:19935,U:19936,U:19956,U:19995,U:19998,U:20003,U:20004,U:20019,U:20031,U:20082,U:20117,U:20120,U:20126,U:20129,U:20146,U:20154,U:20164,U:20206,U:20217,U:20249,U:20262,U:20279,U:20288,U:20309,U:20313,U:20326,U:20359,U:20360,U:20366,U:20380,U:20389,U:20409,U:20411,U:20423,U:20424,U:20425,U:20445,U:20449,U:20464,U:20465,U:20518,U:20522,U:20525,U:20540,U:20560,U:20665,U:20678,U:20679,U:20710,U:20717,U:20742,U:20752,U:20762,U:20791,U:20817,U:20842,U:20848,U:20851,U:20865,U:20872,U:20876,U:20884,U:20919,U:21000,U:21016,U:21060,U:21083,U:21104,U:21111,U:21131,U:21167,U:21186,U:21206,U:21207,U:21212,U:21247,U:21261,U:21282,U:21298,U:21303,U:21318,U:21320,U:21333,U:21344,U:21354,U:21358,U:21360,U:21364,U:21366,U:21383,U:21405,U:21454,U:21468,U:21476,U:21514,U:21524,U:21525,U:21556,U:21566,U:21568,U:21576,U:21609,U:21621,U:21625,U:21644,U:21649,U:21655,U:21663,U:21674,U:21698,U:21702,U:21710,U:21742,U:21780,U:21784,U:21800,U:21803,U:21834,U:21842,U:21847,U:21868,U:21898,U:21902,U:21923,U:21948,U:21967,U:22029,U:22043,U:22045,U:22053,U:22055,U:22105,U:22109,U:22123,U:22124,U:22341,U:22692,U:22695,U:22739,U:22799,U:22846,U:22914,U:22986,U:22996,U:23040,U:23176,U:23354,U:23531,U:23557,U:23608,U:23679,U:23781,U:23965,U:23980,U:24007,U:24279,U:24511,U:24594,U:24606,U:24644,U:24854,U:24910,U:25003,U:25157,U:25240,U:25280,U:25337,U:25375,U:25462,U:25541,U:25546,U:25709,U:25931,U:26407,U:26415,U:26720,U:26872,U:26966,U:27015,U:27195,U:27444,U:27473,U:27482,U:27707,U:27892,U:27899,U:28122,U:28369,U:28465,U:28493,U:28543,U:28547,U:28641,U:28840,U:28973,U:29078,U:29243,U:29256,U:29810,U:29823,U:29977,U:30263,U:30303,U:30365,U:30544,U:30656,U:30697,U:30704,U:30718,U:30975,U:31059,U:31073,U:31109,U:31189,U:31195,U:31335,U:31337,U:31365,U:31625,U:31681,U:31731,U:31891,U:32345,U:32385,U:32528,U:32768,U:32769,U:32770,U:32771,U:32772,U:32773,U:32774,U:32775,U:32776,U:32777,U:32778,U:32779,U:32780,U:32798,U:32815,U:32818,U:32931,U:33030,U:33249,U:33281,U:33354,U:33355,U:33459,U:33717,U:33744,U:33866,U:33872,U:34038,U:34079,U:34125,U:34358,U:34422,U:34433,U:34555,U:34570,U:34577,U:34578,U:34579,U:34580,U:34758,U:34796,U:34855,U:34861,U:34862,U:34892,U:35438,U:35702,U:35777,U:35794,U:36108,U:36206,U:36384,U:36458,U:36489,U:36669,U:36778,U:36893,U:36945,U:37144,U:37212,U:37393,U:37444,U:37602,U:37761,U:37783,U:37813,U:37843,U:38037,U:38063,U:38293,U:38412,U:38498,U:38615,U:39213,U:39217,U:39632,U:39683,U:39714,U:39723,U:39888,U:40019,U:40116,U:40441,U:40539,U:40622,U:40708,U:40711,U:40724,U:40732,U:40805,U:40847,U:40866,U:40915,U:41058,U:41081,U:41308,U:41370,U:41446,U:41524,U:41638,U:41702,U:41774,U:41896,U:41967,U:41971,U:42056,U:42172,U:42313,U:42431,U:42434,U:42508,U:42557,U:42577,U:42627,U:42639,U:43094,U:43195,U:43370,U:43514,U:43686,U:43824,U:43967,U:44101,U:44160,U:44179,U:44185,U:44190,U:44253,U:44334,U:44508,U:44923,U:44946,U:44968,U:45247,U:45380,U:45441,U:45685,U:45722,U:45818,U:45928,U:46093,U:46532,U:46836,U:47624,U:47765,U:47772,U:47808,U:47915,U:47981,U:48078,U:48189,U:48255,U:48455,U:48489,U:48761,U:49152,U:49153,U:49154,U:49155,U:49156,U:49157,U:49158,U:49159,U:49160,U:49161,U:49162,U:49163,U:49165,U:49166,U:49167,U:49168,U:49169,U:49170,U:49171,U:49172,U:49173,U:49174,U:49175,U:49176,U:49177,U:49178,U:49179,U:49180,U:49181,U:49182,U:49184,U:49185,U:49186,U:49187,U:49188,U:49189,U:49190,U:49191,U:49192,U:49193,U:49194,U:49195,U:49196,U:49197,U:49198,U:49199,U:49200,U:49201,U:49202,U:49204,U:49205,U:49207,U:49208,U:49209,U:49210,U:49211,U:49212,U:49213,U:49214,U:49215,U:49216,U:49220,U:49222,U:49226,U:49259,U:49262,U:49306,U:49350,U:49360,U:49393,U:49396,U:49503,U:49640,U:49968,U:50099,U:50164,U:50497,U:50612,U:50708,U:50919,U:51255,U:51456,U:51554,U:51586,U:51690,U:51717,U:51905,U:51972,U:52144,U:52225,U:52503,U:53006,U:53037,U:53571,U:53589,U:53838,U:54094,U:54114,U:54281,U:54321,U:54711,U:54807,U:54925,U:55043,U:55544,U:55587,U:56141,U:57172,U:57409,U:57410,U:57813,U:57843,U:57958,U:57977,U:58002,U:58075,U:58178,U:58419,U:58631,U:58640,U:58797,U:59193,U:59207,U:59765,U:59846,U:60172,U:60381,U:60423,U:61024,U:61142,U:61319,U:61322,U:61370,U:61412,U:61481,U:61550,U:61685,U:61961,U:62154,U:62287,U:62575,U:62677,U:62699,U:62958,U:63420,U:63555,U:64080,U:64481,U:64513,U:64590,U:64727,U:65024'

def _create_unauthorized_open_port_issue(ip, port, protocol):
    issue = {
        'Severity': 'High',
        'Summary': ip + ': ' + str(port) + '/' + str(protocol) + ' open (unauthorized)',
        'Description': 'Unauthorized open port for this host',
        'URLs': [{'URL': ip}],
        'Ports': [port],
        'Classification': {
            'cwe_id': '200',
            'cwe_url': 'http://cwe.mitre.org/data/definitions/200.html'
        }        
    }
    return issue

def _create_authorized_open_port_issue(ip, port, protocol):
    issue = {
        'Severity': 'Info',
        'Summary': ip + ': ' + str(port) + '/' + str(protocol) + ' open (authorized)',
        'Description': 'Authorized open port for this host',
        'URLs': [{'URL': ip}],
        'Ports': [port],
        'Classification': {
            'cwe_id': '200',
            'cwe_url': 'http://cwe.mitre.org/data/definitions/200.html'
        }        
    }
    return issue

def _create_banner_issue(ip, port, protocol, banner):
    issue = {
        'Severity': 'Low',
        'Summary': ip + ': ' + str(port) + '/' + str(protocol) + ' open: "' + banner + '" (information disclosure)',
        'Description': 'Information disclosure',
        'URLs': [{'URL': ip}],
        'Ports': [port],
        'Classification': {
            'cwe_id': '200',
            'cwe_url': 'http://cwe.mitre.org/data/definitions/200.html'
        }
    }
    return issue

def _validate_ports(ports):
    # 21-25,139,8080,U:53,U:111,U:137
    return re.match(r"((U:)?\d+(-\d+)?)(,(U:)?\d+(-\d+)?)*", ports)

def _validate_source_port(source_port):
    try:
        res = int(source_port)
        if (res > 0) and (res < 65536):
            return True
        return False
    except ValueError:
        return False

def _validate_rate(rate):
    try:
        int(rate)
        return True
    except ValueError:
        return False

def parse_banners(version, banners):
    # parse HTTP headers
    if version == 'http':
        if 'HTTP/' == banners[:5]:
            # HTTP header
            headers = []
            for header in ['Server', 'X-Powered-By']:
                res = re.match('.*%s:\s([a-zA-Z0-9_]*).*' % header, banners)
                if res:
                    headers.append(res.group(1))
            return headers
    # manage differently following banners (too verbose)
    elif version in ['X509', 'ssl', 'title']:
        return []
    return [banners]

def parse_masscan_output(output):

    ips = collections.OrderedDict()

    for line in output.split('\n'):

        # Discovered open port 80/tcp on 1.2.3.4
        match = re.match('^Discovered\sopen\sport\s(\d+)/(\S+)\son\s([0-9.]+)\s*$', line)

        if match:
            port = match.group(1)
            protocol = match.group(2)
            ip = match.group(3)
            if ip not in ips:
                ips[ip] = []
            ips[ip].append({'port': int(port), 'protocol': protocol})

        # Banner on port 80/tcp on 1.2.3.4: [title] 302 Found
        # Banner on port 80/tcp on 1.2.3.4: [http] HTTP/1.1 200 OK\x0d\x0aDate: Fri, 20 Jun 2014 17:26:35 GMT\x0d\x0aServer: Apache\x0d\x0aX-Powered-By: PHP/5.3.2-1ubuntu4.22\x0d\x0aVary: Accept-Encoding\x0d\x0aConnection: close\x0d\x0aContent-Type: text/html\x0d\x0a\x0d
        match = re.match('^Banner\son\sport\s(\d+)/(\S+)\son\s([0-9.]+):\s\[(\S+)\]\s(.*)$', line)

        if match:
            port = match.group(1)
            protocol = match.group(2)
            ip = match.group(3)
            version = match.group(4)
            banners = parse_banners(version, match.group(5))
            if ip not in ips:
                ips[ip] = []
            ips[ip].append({'port': int(port), 'protocol': protocol, 'version': version, 'banners': banners})

    return ips

def find_baseline_ports(ip, baseline):
    for info in baseline:
        if ip in info['address']:
            return {'udp': info['udp'], 'tcp': info['tcp']}
    return {'udp': [], 'tcp': []}

class MASSCANPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "MASSCAN"
    PLUGIN_VERSION = "0.1"
    PLUGIN_WEIGHT = "light"

    MASSCAN_NAME = "masscan"

    def ips_to_issues(self, ips):
        issues = []
        for ip in ips:
            baseline_ports = find_baseline_ports(ip, self.baseline)
            for info in ips[ip]:
                if 'banners' not in info:
                    if (info['protocol'] == 'tcp') and ('tcp' in baseline_ports):
                        if (str(info['port']) not in baseline_ports['tcp']):
                            issues.append(_create_unauthorized_open_port_issue(ip, info['port'], 'tcp'))
                        else:
                            issues.append(_create_authorized_open_port_issue(ip, info['port'], 'tcp'))
                    if (info['protocol'] == 'udp') and ('udp' in baseline_ports):
                        if (str(info['port']) not in baseline_ports['udp']):
                            issues.append(_create_unauthorized_open_port_issue(ip, info['port'], 'udp'))
                        else:
                            issues.append(_create_authorized_open_port_issue(ip, info['port'], 'udp'))

                else:
                    for banner in info['banners']:
                        if banner.lower() not in self.banners:
                            issues.append(_create_banner_issue(ip, info['port'], info['protocol'], banner))

        return issues

    def do_start(self):

        path = self.locate_program(self.MASSCAN_NAME)

        if not path:
            raise Exception('Cannot find %s in path' % self.MASSCAN_NAME)

        args = [path]

        self.masscan_stdout = ''
        self.masscan_stderr = ''

        if 'report_dir' in self.configuration:
            self.report_dir = self.configuration['report_dir']
        else:
            self.report_dir = os.path.dirname(os.path.realpath(__file__)) + "/artifacts/"

        self.banners = []
        if 'banners' in self.configuration:
            self.banners = self.configuration.get('banners')

        self.baseline = []            
        if 'baseline' in self.configuration:
            self.baseline = self.configuration.get('baseline')

        try:
            target = netaddr.IPNetwork(self.configuration['target'])
        except Exception:
            try:
                url = urlparse(self.configuration['target'])
                target = url.hostname
            except Exception:
                raise Exception('Input target is not an IP address or a CIDR or a valid URL')

        args += [str(target)]
        ports = self.configuration.get('ports')
        if ports:
            if not _validate_ports(ports):
                raise Exception('Invalid ports specification')
            args += ['-p', ports]
        else:
            ports = default_tcp_ports + ',' + default_udp_ports
            args += ['-p', ports]

        source_port = self.configuration.get('source-port')
        if source_port:
            if not _validate_source_port(source_port):
                raise Exception('Invalid source-port specification')
            args += ['--source-port', source_port]

        rate = self.configuration.get('rate')
        if rate:
            if not _validate_rate(rate):
                raise Exception('Invalid rate specification')
            args += ['--rate', rate]

        interface = self.configuration.get('interface')
        if interface:
            args += ['--interface', interface]

        args += ['--banners']

        self.output_id = str(uuid.uuid4())
        self.xml_output = self.report_dir + "XMLOUTPUT_" + self.output_id + ".xml"
        args += ["-oX", self.xml_output]

        self.spawn('/usr/bin/sudo', args)

    def do_process_stdout(self, data):
        self.masscan_stdout += data

    def do_process_stderr(self, data):
        self.masscan_stderr += data

    def do_process_ended(self, status):
        if self.stopping and status == 9:
            self.report_finish('STOPPED')
        elif status == 0:
            ips = parse_masscan_output(self.masscan_stdout)
            issues = self.ips_to_issues(ips)
            self.report_issues(issues)
            self._save_artifacts()
            self.report_finish()
        else:
            self._save_artifacts()
            failure = {
                "hostname": socket.gethostname(),
                "exception": self.stderr,
                "message": "Plugin failed"
            }
            self.report_finish("FAILED", failure)

    def _save_artifacts(self):
        stdout_log = self.report_dir + "STDOUT_" + self.output_id + ".txt"
        stderr_log = self.report_dir + "STDERR_" + self.output_id + ".txt"
        output_artifacts = []

        if self.masscan_stdout:
            with open(stdout_log, 'w') as f:
                f.write(self.masscan_stdout)
            output_artifacts.append(stdout_log)
        if self.masscan_stderr:
            with open(stderr_log, 'w') as f:
                f.write(self.masscan_stderr)
            output_artifacts.append(stderr_log)

        if output_artifacts:
            self.report_artifacts("Masscan Output", output_artifacts)
        if os.path.isfile(self.xml_output):
            self.report_artifacts("Masscan Report", [self.xml_output])
