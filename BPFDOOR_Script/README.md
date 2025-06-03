# 🐚 BPFdoor Malware Detection Script (BPFdoor 탐지 스크립트)

본 스크립트는 리눅스 서버 내에 존재할 수 있는 **BPFdoor 백도어 악성코드**의 흔적을 확인하는 데 도움을 줍니다.

This script helps detect traces of the **BPFdoor backdoor malware** on Linux servers.

---

## ✅ 사용 방법 / How to Use 

1. **스크립트에 실행 권한 부여 / Grant execute permission:**
   ```bash
chmod +x script.sh

sudo ./script.sh


(선택) bpftool 사용 / (Optional) Use bpftool:
bpftool은 BPFdoor 탐지에 도움을 주는 유틸리티입니다.
사용하려면 script.sh와 동일한 디렉토리에 배치하세요.

Place bpftool in the same folder as script.sh if you wish to use it.



스크립트 실행 시 서버에 일시적 부하가 발생할 수 있습니다.
This script may cause slight load on the system.

이 도구는 보조 진단 도구일 뿐이며, 모든 위협을 100% 탐지하는 것은 아닙니다.
This is an auxiliary diagnostic tool, and does not guarantee complete detection.

기업 환경에서 사용 시 보안팀과 협의 후 사용을 권장합니다.
In corporate environments, consult your security team before deployment.

