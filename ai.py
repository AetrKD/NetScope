import os
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

# Initialize Gemini
API_KEY = os.getenv("GEMINI_API_KEY")
if API_KEY:
    genai.configure(api_key=API_KEY)

# Use gemini-2.5-flash or flash depending on preference. flash is faster for UI.
MODEL_NAME = "gemini-2.5-flash"

def analyze_packet_data(packets):
    """
    Analyzes one or more packets.
    :param packets: list of dict representing packet data
    """
    if not API_KEY:
        return "⚠️ 오류: GEMINI_API_KEY가 설정되지 않았습니다."

    if not packets:
        return "분석할 패킷 데이터가 없습니다."

    try:
        model = genai.GenerativeModel(MODEL_NAME)
        
        prompt = (
            "다음은 네트워크 캡처를 통해 수집된 패킷 데이터입니다. "
            "네트워크 보안 전문가로서 이 패킷들의 의심스러운 징후(예: 공격 시도, 비정상 트래픽, 평문 노출 등)를 핵심만 요약하여 분석해주세요.\n"
            "절대 장황하게 설명하지 마시고, 가장 중요한 3~4가지 포인트만 간결하게 총 5줄 이내로 정리해주세요.\n"
            "응답은 마크다운(Markdown) 형식으로 작성하되, 결론에는 반드시 '위험도: [안전/주의/위험]'을 명시해주세요.\n\n"
        )
        
        for p in packets:
            prompt += f"- 패킷 번호: {p.get('no')}\n"
            prompt += f"  - 시간: {p.get('time')}\n"
            prompt += f"  - 출발지: {p.get('src')}\n"
            prompt += f"  - 목적지: {p.get('dst')}\n"
            prompt += f"  - 프로토콜: {p.get('proto')}\n"
            prompt += f"  - 크기: {p.get('len')} bytes\n"
            prompt += f"  - 요약: {p.get('summary')}\n"
            if p.get('raw'):
                prompt += f"  - 헥스 덤프(일부): {p.get('raw')[:1000]}\n"
            prompt += "\n"
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"⚠️ AI 분석 중 오류가 발생했습니다: {str(e)}"

def assess_ip_risk(ip_address, packets_history):
    """
    Analyzes the traffic history of a specific IP for risk assessment.
    """
    if not API_KEY:
        return "⚠️ 오류: GEMINI_API_KEY가 설정되지 않았습니다."

    if not packets_history:
        return f"{ip_address} 에 대한 최근 패킷 기록이 부족하여 분석할 수 없습니다."

    try:
        model = genai.GenerativeModel(MODEL_NAME)
        
        prompt = (
            f"다음은 {ip_address} IP와 관련된 최근 패킷 트래픽 히스토리입니다. "
            "이 트래픽 패턴을 분석하여 분산 서비스 거부 공격(DDoS), 포트 스캐닝, 무차별 대입(Brute Force) 공격 등의 "
            "징후가 있는지 판별해주세요.\n"
            "절대 장황하게 설명하지 마시고, 핵심적인 분석 결과만 3~4가지 포인트로 간결하게 총 5줄 이내로 요약해주세요.\n"
            "마지막 줄에는 반드시 IP의 종합 위험도(안전, 낮음, 중간, 높음, 매우 높음)를 명시해주세요.\n"
            "응답은 마크다운(Markdown) 형식으로 작성해주세요.\n\n"
            "### 패킷 기록 (최대 100개 요약)\n"
        )
        
        for p in packets_history[:100]:
            prompt += f"[{p.get('time')}] {p.get('src')} -> {p.get('dst')} | {p.get('proto')} | {p.get('len')} bytes | {p.get('summary')}\n"
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"⚠️ 위험도 분석 중 오류가 발생했습니다: {str(e)}"
