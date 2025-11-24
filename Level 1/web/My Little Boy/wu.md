Mở DevTools -> Console rồi chạy code sau
```javascript
/********************************************************************
 * SCRIPT GIẢI CTF "MY LITTLE BOY" - PHIÊN BẢN TỔNG HỢP HOÀN HẢO
 *
 * SỬA LỖI CHÍ MẠNG:
 * - Loại bỏ hoàn toàn cấu trúc if/else gây ra điểm mù.
 * - Trong mỗi chu kỳ, bot sẽ kiểm tra TẤT CẢ các điều kiện một cách
 *   độc lập và thực hiện MỌI hành động cần thiết cùng lúc.
 *
 * KẾT HỢP CÁC CHIẾN LƯỢC:
 * 1. Dọn dẹp cấp tốc: Gửi nhiều lệnh "scoop" khi có nhiều phân.
 * 2. Ngưỡng phòng thủ: Giữ tất cả các chỉ số ở mức siêu an toàn.
 * 3. Không điểm mù: Không bao giờ bỏ qua chỉ số đói hoặc hạnh phúc,
 *    ngay cả khi đang bận dọn dẹp.
 ********************************************************************/

(async () => {
    // --- CẤU HÌNH ---
    const BOOST_SPEED = 50.0;
    const BOT_INTERVAL_MS = 90;

    let botIntervalId = null;

    // --- BỘ NÃO CỦA BOT ---
    async function autoCare() {
        try {
            const state = await getState();
            if (!state || !state.pet) return;
            const pet = state.pet;

            if (pet.age >= 10.0) {
                console.log("%c[AutoBot] CHIẾN THẮNG! Pet đã đạt 10 tuổi. Chúc mừng!", "color: #00ff00; font-size: 18px; font-weight: bold;");
                stopBot();
                await refresh();
                return;
            }

            if (!pet.alive) {
                console.error("[AutoBot] THẤT BẠI! Pet đã chết. Hãy reset và chạy lại script.");
                stopBot();
                return;
            }
            
            console.log(`[AutoBot] Tuổi: ${pet.age.toFixed(2)} | Đói: ${pet.hunger.toFixed(1)} | Vui: ${pet.happiness.toFixed(1)} | Sạch: ${pet.hygiene.toFixed(1)} | Phân: ${state.poop_count}`);

            // --- LOGIC TỔNG HỢP - KIỂM TRA TẤT CẢ TRONG MỖI CHU KỲ ---

            // 1. Xử lý các yêu cầu khẩn cấp
            if (state.pet_request_active) {
                console.log("%c[AutoBot] Hành động: Vuốt ve", "color: orange");
                doAction('pet');
            }
            if (state.poop_count > 0) {
                console.log(`%c[AutoBot] Hành động: Dọn dẹp cấp tốc x${state.poop_count}`, "color: red");
                for (let i = 0; i < state.poop_count; i++) {
                    doAction('scoop');
                }
            }

            // 2. Luôn kiểm tra các chỉ số sinh tồn cơ bản
            if (pet.hunger > 45) {
                console.log("%c[AutoBot] Hành động: Cho ăn", "color: #ff5555");
                doAction('feed');
            }
            
            const hygieneThreshold = (state.poop_count > 0) ? 80 : 55;
            if (pet.hygiene < hygieneThreshold) {
                console.log(`%c[AutoBot] Hành động: Tắm rửa`, "color: #55ffff");
                doAction('clean');
            }
            
            if (pet.happiness < 50) {
                console.log(`%c[AutoBot] Hành động: Chơi đùa`, "color: #55aaff");
                doAction('play');
            }

        } catch (error) {
            console.error("[AutoBot] Gặp lỗi, dừng bot:", error);
            stopBot();
        }
    }

    // --- CÁC HÀM ĐIỀU KHIỂN ---
    function startBot() {
        if (botIntervalId) return;
        console.log(`%c[AutoBot] Bắt đầu phiên bản tổng hợp hoàn hảo.`, "color: #00aaff; font-weight: bold;");
        botIntervalId = setInterval(autoCare, BOT_INTERVAL_MS);
    }

    function stopBot() {
        if (botIntervalId) {
            clearInterval(botIntervalId);
            botIntervalId = null;
            console.log("%c[AutoBot] Bot đã dừng.", "color: #ffaa00; font-weight: bold;");
        }
    }
    
    window.stopBot = stopBot;

    // --- TIẾN TRÌNH CHÍNH ---
    console.log("--- BẮT ĐẦU SCRIPT PHIÊN BẢN CUỐI CÙNG ---");

    try {
        console.log(`[Bước 1] Đang tăng tốc độ lên ${BOOST_SPEED}x...`);
        const boostResponse = await fetch("/dev/boost", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Turbo": "banana" },
            body: JSON.stringify({ x: BOOST_SPEED })
        });
        if (!boostResponse.ok) throw new Error('Yêu cầu boost thất bại!');
        await boostResponse.json();
        console.log(`[Bước 1] THÀNH CÔNG!`);
    } catch (error) {
        console.error("[LỖI] Không thể tăng tốc. Script đã dừng.", error);
        return;
    }

    console.log("[Bước 2] Khởi động bot tự động...");
    startBot();

})();
```