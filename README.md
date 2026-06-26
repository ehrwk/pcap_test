## Execution Video

GitHub의 파일 업로드 용량 제한(최대 25MB)으로 인해 실행 영상은 Google Drive에 업로드하였습니다.

실행 영상 링크:

* **https://drive.google.com/file/d/1TuMVG-7RXPdN3cSGcpzT4cdiLmqvwRpK/view?usp=drive_link**


## Files

* `makefile`과 `pcap-test.pro`는 강사님께서 제공해주신 코드를 그대로 사용하였습니다.
* `pcap-test.c`는 과제 요구사항에 맞게 수정 및 구현하였습니다.
* `pcap_header.h`는 `libnet-headers.h`를 기반으로 작성하였으며, 패킷 정보를 저장하는 `PacketInfo` 구조체와 이를 초기화하는 `init_packet_info()` 함수를 추가하였습니다.

* `pcap-test.c`는 `main()`에서 `parse_packet(packet, header->caplen)`을 호출하도록 수정하였으며, 과제 요구사항에 따라 다음 정보를 출력하도록 구현하였습니다.

  * Ethernet Header의 Source MAC / Destination MAC
  * IPv4 Header의 Source IP / Destination IP
  * TCP Header의 Source Port / Destination Port
  * Payload(Data)의 Hexadecimal Value (최대 20바이트)

* 구현 과정에서 ChatGPT를 참고하여 코드 작성 및 디버깅을 진행하였습니다.
