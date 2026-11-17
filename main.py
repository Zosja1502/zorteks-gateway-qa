import time
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Vanguard Terminal + Zorteks QA Inspector",
    description="Корпоративный платёжный шлюз и система автоматического QA-аудита (zorteks.ru)",
    version="2.4.0",
)

# Состояние в памяти для демонстрации работы терминала
account_balance = 42_850_000.00
processed_keys = {"req-aa10e8-01", "req-c723f1-99", "req-00b8c4-12"}
ledger: List[dict] = [
    {"time": "14:32:01", "tx_id": "tx_9401284", "counterparty": "ООО «Норд-Телеком»", "amount": 45000.00, "key": "req-aa10e8-01", "status": "200 SETTLED"},
    {"time": "14:28:44", "tx_id": "tx_9401283", "counterparty": "АО «Метротек Дата»", "amount": 320000.00, "key": "req-c723f1-99", "status": "200 SETTLED"},
    {"time": "14:15:10", "tx_id": "tx_9401282", "counterparty": "ПАО «Энергосбыт»", "amount": 18500.00, "key": "req-00b8c4-12", "status": "200 SETTLED"},
]

class PaymentRequest(BaseModel):
    amount: float = Field(..., gt=0, description="Сумма списания")
    currency: str = Field(default="RUB", pattern="^(RUB|USD|CNY)$")
    counterparty: str = Field(..., min_length=3, description="ИНН или наименование контрагента")
    comment: str = Field(default="", description="Назначение платежа")

class SanitizeRequest(BaseModel):
    text: str = Field(..., description="Входящий текст или комментарий для NLP-проверки")

def check_prompt_injection(text: str) -> List[str]:
    threats = []
    lowered = text.lower()
    patterns = {
        "ignore instructions": "Попытка перехвата управления (Prompt Injection)",
        "dump token": "Попытка извлечения секретных токенов",
        "drop table": "Обнаружена SQL-инъекция",
        "sk-": "Утечка приватного API-ключа",
    }
    for pattern, reason in patterns.items():
        if pattern in lowered:
            threats.append(reason)
    return threats

@app.post("/api/v1/payments/process")
async def process_payment(
    payload: PaymentRequest,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key")
):
    global account_balance
    start = time.perf_counter()

    if not idempotency_key:
        raise HTTPException(status_code=400, detail="Отсутствует обязательный заголовок Idempotency-Key")

    # 1. Проверка защиты от дублей (409 Conflict)
    if idempotency_key in processed_keys:
        raise HTTPException(
            status_code=409,
            detail=f"Conflict: Повторная транзакция отклонена. Ключ '{idempotency_key}' уже обработан."
        )

    # 2. Проверка суточного лимита антифрода (403 Forbidden)
    if payload.amount > 500_000:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Превышен суточный лимит антифрода (500 000.00 ₽ на транзакцию)."
        )

    # 3. Встроенная проверка комментария на инъекции
    threats = check_prompt_injection(payload.comment)
    if threats:
        raise HTTPException(status_code=422, detail=f"LLM Sanitizer Blocked: {', '.join(threats)}")

    # Проведение расчёта
    processed_keys.add(idempotency_key)
    account_balance -= payload.amount
    tx_id = f"tx_{int(time.time() * 1000) % 10000000}"
    record = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "tx_id": tx_id,
        "counterparty": payload.counterparty,
        "amount": payload.amount,
        "key": idempotency_key,
        "status": "200 SETTLED"
    }
    ledger.insert(0, record)
    latency_ms = round((time.perf_counter() - start) * 1000, 2)

    return {
        "status": "SETTLED",
        "transaction": record,
        "remaining_balance": account_balance,
        "latency_ms": latency_ms
    }

@app.post("/api/v1/security/ai-sanitize")
async def ai_sanitize(data: SanitizeRequest):
    threats = check_prompt_injection(data.text)
    is_safe = len(threats) == 0
    return {
        "safe": is_safe,
        "verdict": "CLEAN" if is_safe else "BLOCKED_INJECTION",
        "threats": threats
    }

@app.get("/api/v1/health/telemetry")
async def get_telemetry():
    return {
        "status": "ONLINE",
        "node": "msk-dc-01.vanguard.internal",
        "p99_latency_ms": 0.18,
        "balance": account_balance,
        "ledger": ledger
    }

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()
