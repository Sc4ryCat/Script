# 🌐 WHOIS Domain Lookup Script

이 스크립트는 사용자가 입력한 도메인에 대한 WHOIS 정보를 수집하고, 해당 결과를 `.txt` 파일로 저장한 뒤 메모장으로 자동 열어줍니다.  
This script allows you to input a domain, fetch its WHOIS information, save the results to a text file, and open it in Notepad.

## ✅ 사용 방법 / How to Use

1. 필요한 라이브러리 설치: pip install python-whois

2. 스크립트 실행: python whois_lookup.py

3. Domain 입력을 해주세요 : example.com

4. 결과가 `example_com.txt` 형태로 저장되며 자동으로 메모장에서 열립니다.

5. 콘솔 출력 내용:
- 도메인 이름
- 등록 기관
- 등록 URL
- WHOIS 서버
- 생성일 / 수정일 / 만료일
- 네임서버
- 이메일 주소
- DNSSEC 여부


## 📦 주요 기능

- `whois` 모듈로 도메인 정보 수집
- 결과를 텍스트로 저장 및 자동 열기
- 주요 필드 정보 정리 출력

## ⚠️ 주의사항

- 일부 도메인은 특정 필드가 비어 있거나 None일 수 있습니다.
- 값이 리스트나 datetime 형식일 수 있으므로 출력 시 타입 확인이 필요합니다.
- 현재 Windows 환경 기준(`notepad`)으로 동작합니다.

## 🔧 개선 아이디어

- 예외 처리(`try-except`) 추가
- OS별 텍스트 뷰어 자동 감지 (`notepad`, `xdg-open`, `open` 등)
- GUI 버전 확장 (tkinter 등)

## 🧑‍💻 제작자

By [Sc4ryCat](https://github.com/Sc4ryCat)



