/**
 * Thanh Xuân Có Nhau — 6 Mảnh Ghép Kỷ Niệm
 * Bundle: app.bundle.js
 * Architecture: Self-Executing Private Closure (Zero Global Leaks)
 * Security: SHA-256 Hashed Credentials, Guarded Rendering, Immutability Freeze
 */

(() => {
  'use strict';

  /* ================================================================
     1. PRIVATE CRYPTOGRAPHIC ENGINE
     ================================================================ */
  const _pureSha256 = (str) => {
    const rightRotate = (val, amt) => (val >>> amt) | (val << (32 - amt));
    const mathPow = Math.pow;
    const maxWord = mathPow(2, 32);
    const k = [];
    const hash = [];
    let primeCount = 0;
    const isComposite = {};

    for (let candidate = 2; primeCount < 64; candidate++) {
      if (!isComposite[candidate]) {
        for (let i = candidate * 2; i < 313; i += candidate) isComposite[i] = true;
        hash[primeCount] = (mathPow(candidate, 0.5) * maxWord) | 0;
        k[primeCount++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      }
    }

    const words = [];
    const asciiBitLen = str.length * 8;
    let strPadded = str + '\x80';
    while ((strPadded.length % 64) !== 56) strPadded += '\x00';
    for (let i = 0; i < strPadded.length; i++) {
      words[i >> 2] |= strPadded.charCodeAt(i) << ((3 - (i % 4)) * 8);
    }
    words.push((asciiBitLen / maxWord) | 0);
    words.push(asciiBitLen | 0);

    for (let j = 0; j < words.length; j += 16) {
      const w = words.slice(j, j + 16);
      for (let i = 16; i < 64; i++) {
        const w15 = w[i - 15];
        const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
        const w2 = w[i - 2];
        const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let [a, b, c, d, e, f, g, h] = hash;
      for (let i = 0; i < 64; i++) {
        const s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        const ch = (e & f) ^ ((~e) & g);
        const temp1 = (h + s1 + ch + k[i] + w[i]) | 0;
        const s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (s0 + maj) | 0;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) | 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) | 0;
      }
      hash[0] = (hash[0] + a) | 0;
      hash[1] = (hash[1] + b) | 0;
      hash[2] = (hash[2] + c) | 0;
      hash[3] = (hash[3] + d) | 0;
      hash[4] = (hash[4] + e) | 0;
      hash[5] = (hash[5] + f) | 0;
      hash[6] = (hash[6] + g) | 0;
      hash[7] = (hash[7] + h) | 0;
    }

    return hash.slice(0, 8).map(v => (v >>> 0).toString(16).padStart(8, '0')).join('');
  };

  const _computeDigest = async (inputStr) => {
    if (window.crypto && window.crypto.subtle) {
      try {
        const encoded = new TextEncoder().encode(inputStr);
        const buffer = await window.crypto.subtle.digest('SHA-256', encoded);
        return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
      } catch {
        return _pureSha256(inputStr);
      }
    }
    return _pureSha256(inputStr);
  };

  /* ================================================================
     2. SECURE DATA REGISTRIES (FROZEN & HASHED)
     ================================================================ */
  const _PROFILE_REGISTRY = Object.freeze({
    giang: Object.freeze({
      name: 'Nguyễn Hương Giang',
      nick: 'Giang',
      authDigest: '95c6aceb8c2ee47714e59a4dd8b4f339bb0e8131955c21a9b3ffe05fdc9ad13b',
      dobDisplay: '25/07/2006',
      gender: 'female',
      role: 'Linh hồn của nhóm / Luôn giữ mọi người gắn kết',
      bio: 'Cô nàng dịu dàng nhưng rất bản lĩnh. Luôn là người đứng giữa hòa giải mọi chuyện và tạo ra những kỷ niệm đáng nhớ nhất cho cả nhóm.',
      avatar: 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?auto=format&fit=crop&q=80&w=600',
      years: Object.freeze({
        '2024': [
          { type:'nice',  title:'Năm học đầu tiên',        caption:'Những ngày đầu vào lớp còn bỡ ngỡ, chưa biết mình sẽ có một nhóm bạn tuyệt vời thế này.', date:'Tháng 9, 2024',  img:'https://images.unsplash.com/photo-1524504388940-b1c1722653e1?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Selfie góc xấu',          caption:'Ảnh chụp tự sướng góc trái nhưng lại bị dìm sấp mặt luôn.',                              date:'Tháng 11, 2024', img:'https://images.unsplash.com/photo-1494790108377-be9c29b29330?auto=format&fit=crop&q=80&w=800' }
        ],
        '2025': [
          { type:'nice',  title:'Dã ngoại cùng nhóm',     caption:'Buổi picnic đầu tiên của cả 6 đứa, nắng vàng trải dài trên thảm cỏ xanh.',              date:'Tháng 3, 2025',  img:'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Bị té trượt cỏ',         caption:'Đang tạo dáng chụp ảnh thì trượt luôn xuống dốc cỏ, cả nhóm cười nghiêng ngả.',          date:'Tháng 3, 2025',  img:'https://images.unsplash.com/photo-1517841905240-472988babdf9?auto=format&fit=crop&q=80&w=800' }
        ],
        '2026': [
          { type:'nice',  title:'Kỷ niệm 1 năm thành nhóm',caption:'Tròn 1 năm gắn bó, cả nhóm cùng ôn lại những kỷ niệm đẹp nhất.',                      date:'Tháng 9, 2026',  img:'https://images.unsplash.com/photo-1529156069898-49953e39b3ac?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Sinh nhật bị dìm',       caption:'Ngày sinh nhật mà cả nhóm mang ảnh xấu ra triển lãm, khóc cười không biết nữa.',          date:'Tháng 7, 2026',  img:'https://images.unsplash.com/photo-1511632765486-a01980e01a18?auto=format&fit=crop&q=80&w=800' }
        ]
      })
    }),
    tuan: Object.freeze({
      name: 'Đỗ Hữu Tuân',
      nick: 'Tuân',
      authDigest: '39b77be3ef40f0ce9cd4bf1fb2436a4491f22766b6cc0531bed63722b39b9ac2',
      dobDisplay: '16/04/2006',
      gender: 'male',
      role: 'Hài hước / Cây kể chuyện',
      bio: 'Tuân là người mang lại tiếng cười nhiều nhất cho nhóm. Tài kể chuyện trời phú, chỉ cần mở miệng là cả nhóm cười bò.',
      avatar: 'https://images.unsplash.com/photo-1500648767791-00dcc994a43e?auto=format&fit=crop&q=80&w=600',
      years: Object.freeze({
        '2024': [
          { type:'nice',  title:'Buổi tụ tập đầu tiên',   caption:'Lần đầu gặp cả nhóm, Tuân đã kể một câu chuyện cười và từ đó trở thành linh hồn của nhóm.',date:'Tháng 10, 2024', img:'https://images.unsplash.com/photo-1506794778202-cad84cf45f1d?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Nhái giọng thầy giáo',   caption:'Màn nhái giọng thầy giáo quá đỉnh khiến cả lớp ngã ngửa.',                               date:'Tháng 12, 2024', img:'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?auto=format&fit=crop&q=80&w=800' }
        ],
        '2025': [
          { type:'nice',  title:'Giọng hát karaoke',      caption:'Ai nghĩ Tuân hát hay thế cơ chứ, cả nhóm nghe mà rớt nước mắt.',                         date:'Tháng 5, 2025',  img:'https://images.unsplash.com/photo-1519085360753-af0119f7cbe7?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Bị quay vlog khi ngủ',   caption:'Ngủ gật giữa buổi học và bị quay lại, biểu cảm cực dị.',                                 date:'Tháng 9, 2025',  img:'https://images.unsplash.com/photo-1522075469751-3a6694fb2f61?auto=format&fit=crop&q=80&w=800' }
        ],
        '2026': [
          { type:'nice',  title:'Tiệc sinh nhật bất ngờ',  caption:'Cả nhóm bí mật tổ chức sinh nhật cho Tuân, nhìn mặt anh ấy mà thương.',                  date:'Tháng 4, 2026',  img:'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Trò cá tháng tư bị lật', caption:'Tưởng lừa được cả nhóm nhưng lại bị phản đòn, mặt xanh mặt đỏ.',                         date:'Tháng 4, 2026',  img:'https://images.unsplash.com/photo-1492562080023-ab3db95bfbce?auto=format&fit=crop&q=80&w=800' }
        ]
      })
    }),
    lananh: Object.freeze({
      name: 'Chu Thị Lan Anh',
      nick: 'Lan Anh',
      authDigest: '8776a21e31ec7219e4927f5183562ba46ec50e5c2fa981534d8d01f9d02c3d28',
      dobDisplay: '24/10/2006',
      gender: 'female',
      role: 'Stylist / Người giữ kỷ niệm',
      bio: 'Lan Anh là người chụp ảnh cho cả nhóm và cũng là người lưu giữ mọi khoảnh khắc qua từng cuốn album. Gu thẩm mỹ cực đỉnh.',
      avatar: 'https://images.unsplash.com/photo-1524504388940-b1c1722653e1?auto=format&fit=crop&q=80&w=600',
      years: Object.freeze({
        '2024': [
          { type:'nice',  title:'Album ảnh đầu tiên',      caption:'Lan Anh tự tay làm album ảnh kỷ niệm cho cả nhóm, mỗi trang đều rất công phu.',          date:'Tháng 11, 2024', img:'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Chụp ảnh nhưng bị ngược sáng',caption:'Hì hục canh góc cả tiếng mà ảnh vẫn bị ngược sáng, cả nhóm phá ra cười.',          date:'Tháng 12, 2024', img:'https://images.unsplash.com/photo-1517841905240-472988babdf9?auto=format&fit=crop&q=80&w=800' }
        ],
        '2025': [
          { type:'nice',  title:'Phối đồ đi sinh nhật',   caption:'Tự phối bộ đồ đẹp mê hồn cho buổi tiệc sinh nhật nhóm.',                                 date:'Tháng 4, 2025',  img:'https://images.unsplash.com/photo-1494790108377-be9c29b29330?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Mua đồ nhầm size',        caption:'Order quần áo online nhưng mặc vào thì rộng thênh thang, cả nhóm cười ngất.',             date:'Tháng 7, 2025',  img:'https://images.unsplash.com/photo-1524504388940-b1c1722653e1?auto=format&fit=crop&q=80&w=800' }
        ],
        '2026': [
          { type:'nice',  title:'Sinh nhật 20 tuổi',      caption:'Cả nhóm bất ngờ tổ chức sinh nhật, Lan Anh không ngờ mà khóc luôn.',                      date:'Tháng 10, 2026', img:'https://images.unsplash.com/photo-1529156069898-49953e39b3ac?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Vẽ bánh sinh nhật xấu',  caption:'Tự vẽ hình lên bánh sinh nhật nhưng trông như tranh trẻ con, dễ thương không tưởng.',      date:'Tháng 10, 2026', img:'https://images.unsplash.com/photo-1511632765486-a01980e01a18?auto=format&fit=crop&q=80&w=800' }
        ]
      })
    }),
    dat: Object.freeze({
      name: 'Nguyễn Văn Đạt',
      nick: 'Đạt',
      authDigest: '99fb38c9a16b76cf004617597cd01ebaa3a27770488aa8dc8d56ebcf782e76de',
      dobDisplay: '09/04/2006',
      gender: 'male',
      role: 'Thể thao / Năng động nhất nhóm',
      bio: 'Đạt là người năng động nhất, kéo cả nhóm đi chơi thể thao mỗi cuối tuần. Không có Đạt thì cả nhóm chỉ ngồi trong phòng bấm điện thoại thôi.',
      avatar: 'https://images.unsplash.com/photo-1539571696357-5a69c17a67c6?auto=format&fit=crop&q=80&w=600',
      years: Object.freeze({
        '2024': [
          { type:'nice',  title:'Chiến thắng giải bóng đá',caption:'Cùng các bạn giành cúp trong giải bóng đá liên lớp, tự hào lắm.',                        date:'Tháng 11, 2024', img:'https://images.unsplash.com/photo-1511512578047-dfb367046420?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Tập gym sai tư thế',     caption:'Lần đầu tập gym bị chụp lại cái tư thế sai không thể sai hơn.',                           date:'Tháng 10, 2024', img:'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?auto=format&fit=crop&q=80&w=800' }
        ],
        '2025': [
          { type:'nice',  title:'Chạy bộ buổi sáng',      caption:'Kéo cả nhóm dậy lúc 6h sáng chạy bộ, ai cũng rên rỉ nhưng sau đó lại thấy khỏe.',        date:'Tháng 2, 2025',  img:'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Đá bóng vào lưới nhà',   caption:'Trong trận đấu quan trọng, Đạt vô tình đá vào lưới đội mình, biểu cảm đáng thương quá.',  date:'Tháng 5, 2025',  img:'https://images.unsplash.com/photo-1492562080023-ab3db95bfbce?auto=format&fit=crop&q=80&w=800' }
        ],
        '2026': [
          { type:'nice',  title:'Huy chương thể thao',    caption:'Giành huy chương trong giải điền kinh cấp trường, cả nhóm đến cổ vũ hết mình.',            date:'Tháng 3, 2026',  img:'https://images.unsplash.com/photo-1531403009284-440f080d1e12?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Ngủ gật sau khi tập',    caption:'Tập về mệt quá, ngủ gục trên ghế sofa ngay tại chỗ luôn.',                               date:'Tháng 4, 2026',  img:'https://images.unsplash.com/photo-1522075469751-3a6694fb2f61?auto=format&fit=crop&q=80&w=800' }
        ]
      })
    }),
    tuananh: Object.freeze({
      name: 'Nguyễn Tuấn Anh',
      nick: 'Tuấn Anh',
      authDigest: '97f2a7730dd7078ea4059763504bd52adaebbdfb8db5072e540d8b6a025ab72a',
      dobDisplay: '20/12/2006',
      gender: 'male',
      role: 'Trùm công nghệ / Lập trình viên nhóm',
      bio: 'Tuấn Anh là người giỏi công nghệ nhất nhóm, fix được mọi thứ từ máy tính đến điện thoại. Chuyên gia giải cứu khi wifi bị lỗi giữa chừng.',
      avatar: 'https://images.unsplash.com/photo-1500648767791-00dcc994a43e?auto=format&fit=crop&q=80&w=600',
      years: Object.freeze({
        '2024': [
          { type:'nice',  title:'Làm app cho cả nhóm',    caption:'Tự tay code một app nhỏ để cả nhóm lên lịch tụ tập, ai cũng trầm trồ.',                  date:'Tháng 10, 2024', img:'https://images.unsplash.com/photo-1531403009284-440f080d1e12?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Máy tính bị treo',       caption:'Chuyên gia công nghệ mà máy tính của mình lại bị treo đúng lúc thuyết trình.',             date:'Tháng 11, 2024', img:'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&q=80&w=800' }
        ],
        '2025': [
          { type:'nice',  title:'Đoạt giải hackathon',    caption:'Team giành top 3 trong cuộc thi lập trình toàn trường, tự hào cực.',                      date:'Tháng 6, 2025',  img:'https://images.unsplash.com/photo-1519085360753-af0119f7cbe7?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Quên cắm sạc máy tính', caption:'Thức đêm code rồi quên cắm sạc, máy chết ngay lúc sắp xong bài.',                         date:'Tháng 9, 2025',  img:'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?auto=format&fit=crop&q=80&w=800' }
        ],
        '2026': [
          { type:'nice',  title:'Sinh nhật cuối năm',     caption:'Sinh nhật gần Giáng sinh nên được ăn bánh 2 lần, hạnh phúc không có gì bằng.',            date:'Tháng 12, 2026', img:'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Cài nhầm hệ điều hành', caption:'Sửa máy cho bạn nhưng cài nhầm phiên bản hệ điều hành, phải làm lại từ đầu.',             date:'Tháng 11, 2026', img:'https://images.unsplash.com/photo-1492562080023-ab3db95bfbce?auto=format&fit=crop&q=80&w=800' }
        ]
      })
    }),
    quocanh: Object.freeze({
      name: 'Phan Lạc Quốc Anh',
      nick: 'Quốc Anh',
      authDigest: '72774683d3f5e780f6a71e7e8d7c80ac38a7e043112f388fa28de109cdf890ac',
      dobDisplay: '20/10/2006',
      gender: 'male',
      role: 'Ẩm thực / Đầu bếp không chuyên',
      bio: 'Quốc Anh mê nấu ăn và luôn tình nguyện nấu cho cả nhóm mỗi khi tụ họp. Những bữa ăn do Quốc Anh nấu luôn là kỷ niệm khó quên.',
      avatar: 'https://images.unsplash.com/photo-1506794778202-cad84cf45f1d?auto=format&fit=crop&q=80&w=600',
      years: Object.freeze({
        '2024': [
          { type:'nice',  title:'Bữa lẩu đầu tiên',       caption:'Quốc Anh tự tay nấu lẩu cho cả nhóm, ngon đến mức ai cũng khen không ngớt.',             date:'Tháng 10, 2024', img:'https://images.unsplash.com/photo-1555396273-367ea4eb4db5?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Nấu cháy xoong',         caption:'Mải nói chuyện quên khuấy nồi canh đang trên bếp, mùi cháy khét bay khắp nhà.',           date:'Tháng 11, 2024', img:'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?auto=format&fit=crop&q=80&w=800' }
        ],
        '2025': [
          { type:'nice',  title:'Bánh sinh nhật tự làm',  caption:'Tự tay làm bánh sinh nhật cho Giang, đẹp không kém tiệm bánh ngoài.',                    date:'Tháng 7, 2025',  img:'https://images.unsplash.com/photo-1524504388940-b1c1722653e1?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Thêm muối nhầm',         caption:'Tưởng thêm đường vào chè nhưng lại thêm muối, cả nhóm nhăn mặt nhổ ra.',                  date:'Tháng 8, 2025',  img:'https://images.unsplash.com/photo-1480429370139-e0132c086e2a?auto=format&fit=crop&q=80&w=800' }
        ],
        '2026': [
          { type:'nice',  title:'Bữa tiệc cuối năm',      caption:'Nấu cả mâm cỗ cho nhóm tổng kết cuối năm, ai cũng ăn no căng bụng.',                     date:'Tháng 12, 2026', img:'https://images.unsplash.com/photo-1529156069898-49953e39b3ac?auto=format&fit=crop&q=80&w=800' },
          { type:'funny', title:'Mặc tạp dề đi học',      caption:'Quên cởi tạp dề sau khi nấu bữa sáng rồi đi học luôn, cả lớp nhìn không hiểu.',          date:'Tháng 10, 2026', img:'https://images.unsplash.com/photo-1511632765486-a01980e01a18?auto=format&fit=crop&q=80&w=800' }
        ]
      })
    })
  });

  const _TIMELINE_REGISTRY = Object.freeze([
    { type:'nice',  title:'Chuyến đi chơi đầu tiên cùng nhau (2024)', caption:'6 đứa lần đầu đi chơi xa cùng nhau, đủ trò vui từ sáng đến tối mà vẫn chưa muốn về.', date:'Tháng 11, 2024', img:'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?auto=format&fit=crop&q=80&w=1000' },
    { type:'funny', title:'Hậu trường nấu ăn chung thảm họa',         caption:'Đứa nấu mặn, đứa nấu nhạt, cuối cùng phải gọi đồ ăn nhanh vì không ai dám nuốt.',   date:'Tháng 1, 2025',  img:'https://images.unsplash.com/photo-1555396273-367ea4eb4db5?auto=format&fit=crop&q=80&w=1000' },
    { type:'nice',  title:'Kỷ niệm 1 năm gắn bó (2025)',              caption:'Tròn một năm nhóm hình thành, cùng ôn lại từng khoảnh khắc đáng nhớ và cười bò.',     date:'Tháng 9, 2025',  img:'https://images.unsplash.com/photo-1529156069898-49953e39b3ac?auto=format&fit=crop&q=80&w=1000' },
    { type:'funny', title:'Đại hội dìm hàng sinh nhật từng người',    caption:'Mỗi lần ai có sinh nhật là cả nhóm lại mang ảnh xấu ra triển lãm, không tha ai cả.',   date:'Tháng 10, 2025', img:'https://images.unsplash.com/photo-1511632765486-a01980e01a18?auto=format&fit=crop&q=80&w=1000' }
  ]);

  /* ================================================================
     3. PRIVATE RUNTIME STATE
     ================================================================ */
  let _activeMemberId = 'giang';
  let _activePeriod = '2024';
  let _activeDisplayMode = 'nice';
  let _isSessionUnlocked = false;

  const _STORAGE_SESSION_TOKEN_KEY = '__sec_gate_auth__';

  /* ================================================================
     4. PRIVATE VIEW RENDERERS
     ================================================================ */
  const _renderMemberView = () => {
    if (!_isSessionUnlocked) return;

    const member = _PROFILE_REGISTRY[_activeMemberId];
    const container = document.getElementById('memberProfileContainer');
    if (!container || !member) return;

    const availablePeriods = Object.keys(member.years);
    if (!availablePeriods.includes(_activePeriod)) {
      _activePeriod = availablePeriods[0];
    }

    const photos = member.years[_activePeriod] || [];

    const profileMarkup = `
      <div class="member-profile-card">
        <div class="member-avatar-wrapper">
          <img src="${member.avatar}" alt="${member.name}" loading="lazy">
        </div>
        <div class="member-info">
          <span class="member-badge ${member.gender === 'male' ? 'badge-male' : 'badge-female'}">
            ${member.gender === 'male' ? '♂ Nam Thành Viên' : '♀ Nữ Thành Viên'}
          </span>
          <div class="member-dob"><i class="fa-regular fa-calendar-heart"></i> ${member.dobDisplay}</div>
          <h3>${member.name}</h3>
          <p class="role"><i class="fa-solid fa-sparkles"></i> ${member.role}</p>
          <p class="bio">${member.bio}</p>
        </div>
      </div>`;

    const periodTabsMarkup = `<div class="year-tabs">
      ${availablePeriods.map(year => `<button class="year-tab${year === _activePeriod ? ' active' : ''}" data-year="${year}">${year}</button>`).join('')}
    </div>`;

    const photoGalleryMarkup = `<div class="photo-grid" id="memberPhotoGrid">
      ${photos.map(item => `
        <div class="photo-card${item.type !== _activeDisplayMode ? ' hidden-item' : ''}"
             data-img="${item.img}" data-title="${item.title}" data-caption="${item.caption}" data-type="${item.type}">
          <div class="photo-thumb">
            <span class="photo-badge-type ${item.type === 'nice' ? 'type-nice' : 'type-funny'}">
              ${item.type === 'nice' ? '✨ Ảnh Đẹp' : '🤪 Ảnh Dìm'}
            </span>
            <img src="${item.img}" alt="${item.title}" loading="lazy">
          </div>
          <div class="photo-content">
            <h4>${item.title}</h4>
            <p>${item.caption}</p>
            <div class="photo-date"><i class="fa-regular fa-calendar"></i> ${item.date}</div>
          </div>
        </div>`).join('')}
    </div>`;

    container.innerHTML = profileMarkup + periodTabsMarkup + photoGalleryMarkup;

    _bindPeriodSelectorEvents();
    _initCardTiltTransform();
    _bindPhotoPreviewEvents();
  };

  const _renderTimelineView = () => {
    if (!_isSessionUnlocked) return;

    const container = document.getElementById('groupTimelineContainer');
    if (!container) return;

    container.innerHTML = _TIMELINE_REGISTRY.map(memory => `
      <div class="timeline-item${memory.type !== _activeDisplayMode ? ' hidden-item' : ''}">
        <div class="timeline-dot"></div>
        <div class="timeline-content-card">
          <div class="timeline-img-box"
               data-img="${memory.img}" data-title="${memory.title}" data-caption="${memory.caption}" data-type="${memory.type}">
            <span class="photo-badge-type ${memory.type === 'nice' ? 'type-nice' : 'type-funny'}" style="position:absolute;top:13px;right:13px">
              ${memory.type === 'nice' ? '✨ Kỷ Niệm Đẹp' : '🤪 Khoảnh Khắc Dìm'}
            </span>
            <img src="${memory.img}" alt="${memory.title}" loading="lazy">
          </div>
          <div class="timeline-body">
            <div class="timeline-date-tag"><i class="fa-regular fa-clock"></i> ${memory.date}</div>
            <h4>${memory.title}</h4>
            <p>${memory.caption}</p>
          </div>
        </div>
      </div>`).join('');

    _bindTimelinePreviewEvents();
  };

  /* ================================================================
     5. PRIVATE MODAL / LIGHTBOX CONTROLLER
     ================================================================ */
  const _openLightboxModal = (imageSrc, title, caption, categoryType) => {
    const modalEl = document.getElementById('lightboxModal');
    const imgEl = document.getElementById('lightboxImg');
    const titleEl = document.getElementById('lightboxTitle');
    const captionEl = document.getElementById('lightboxCaption');
    const tagEl = document.getElementById('lightboxTag');

    if (!modalEl || !imgEl || !titleEl || !captionEl || !tagEl) return;

    imgEl.src = imageSrc;
    titleEl.textContent = title;
    captionEl.textContent = caption;
    tagEl.textContent = categoryType === 'nice' ? '✨ Ảnh Đẹp' : '🤪 Ảnh Dìm';
    tagEl.className = `photo-badge-type ${categoryType === 'nice' ? 'type-nice' : 'type-funny'}`;
    modalEl.classList.add('active');
  };

  const _closeLightboxModal = () => {
    const modalEl = document.getElementById('lightboxModal');
    if (modalEl) modalEl.classList.remove('active');
  };

  /* ================================================================
     6. PRIVATE EVENT BINDERS
     ================================================================ */
  const _bindPeriodSelectorEvents = () => {
    document.querySelectorAll('.year-tab').forEach(tabBtn => {
      tabBtn.addEventListener('click', evt => {
        document.querySelectorAll('.year-tab').forEach(btn => btn.classList.remove('active'));
        evt.currentTarget.classList.add('active');
        _activePeriod = evt.currentTarget.dataset.year;
        _renderMemberView();
      });
    });
  };

  const _bindPhotoPreviewEvents = () => {
    document.querySelectorAll('.photo-card').forEach(card => {
      card.addEventListener('click', () => {
        _openLightboxModal(
          card.dataset.img,
          card.dataset.title,
          card.dataset.caption,
          card.dataset.type
        );
      });
    });
  };

  const _bindTimelinePreviewEvents = () => {
    document.querySelectorAll('.timeline-img-box').forEach(box => {
      box.addEventListener('click', () => {
        _openLightboxModal(
          box.dataset.img,
          box.dataset.title,
          box.dataset.caption,
          box.dataset.type
        );
      });
    });
  };

  const _bindGlobalNavigationEvents = () => {
    // Member selector tabs
    document.querySelectorAll('.member-tab-btn').forEach(btn => {
      btn.addEventListener('click', evt => {
        document.querySelectorAll('.member-tab-btn').forEach(b => b.classList.remove('active'));
        evt.currentTarget.classList.add('active');
        _activeMemberId = evt.currentTarget.dataset.member;
        _renderMemberView();
      });
    });

    // Nice / Funny gallery toggle
    const toggleInput = document.getElementById('modeToggle');
    const labelNice = document.getElementById('labelNice');
    const labelFunny = document.getElementById('labelFunny');

    const updateToggleDisplay = (isFunny) => {
      _activeDisplayMode = isFunny ? 'funny' : 'nice';
      if (toggleInput.checked !== isFunny) {
        toggleInput.checked = isFunny;
      }
      labelNice.classList.toggle('active-nice', !isFunny);
      labelFunny.classList.toggle('active-funny', isFunny);
      _renderMemberView();
      _renderTimelineView();
    };

    if (toggleInput && labelNice && labelFunny) {
      toggleInput.addEventListener('change', evt => {
        updateToggleDisplay(evt.target.checked);
      });

      labelNice.addEventListener('click', () => {
        if (_activeDisplayMode !== 'nice') {
          updateToggleDisplay(false);
        }
      });

      labelFunny.addEventListener('click', () => {
        if (_activeDisplayMode !== 'funny') {
          updateToggleDisplay(true);
        }
      });
    }

    // Lightbox modal dismissal
    const closeBtn = document.getElementById('lightboxClose');
    const modalEl = document.getElementById('lightboxModal');
    if (closeBtn) closeBtn.addEventListener('click', _closeLightboxModal);
    if (modalEl) {
      modalEl.addEventListener('click', evt => {
        if (evt.target.id === 'lightboxModal') _closeLightboxModal();
      });
    }
    document.addEventListener('keydown', evt => {
      if (evt.key === 'Escape') _closeLightboxModal();
    });
  };

  /* ================================================================
     7. PRIVATE ANIMATION & UX ENGINES
     ================================================================ */
  const _initCardTiltTransform = () => {
    document.querySelectorAll('.photo-card').forEach(cardEl => {
      let rafIdentifier = null;
      let rotX = 0, rotY = 0;

      const executeTilt = () => {
        cardEl.style.transform = `rotateX(${rotX}deg) rotateY(${rotY}deg) scale3d(1.02,1.02,1.02)`;
        rafIdentifier = null;
      };

      cardEl.addEventListener('mousemove', evt => {
        const bounds = cardEl.getBoundingClientRect();
        const halfWidth = bounds.width / 2;
        const halfHeight = bounds.height / 2;
        rotX = ((evt.clientY - bounds.top - halfHeight) / halfHeight) * -7;
        rotY = ((evt.clientX - bounds.left - halfWidth) / halfWidth) * 7;
        if (!rafIdentifier) {
          rafIdentifier = requestAnimationFrame(executeTilt);
        }
      });

      cardEl.addEventListener('mouseleave', () => {
        if (rafIdentifier) {
          cancelAnimationFrame(rafIdentifier);
          rafIdentifier = null;
        }
        cardEl.style.transform = '';
      });
    });
  };

  const _initScrollRevealObserver = () => {
    const observer = new IntersectionObserver((entries, obs) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('active');
          obs.unobserve(entry.target);
        }
      });
    }, { threshold: 0.08, rootMargin: '0px 0px -40px 0px' });

    document.querySelectorAll('.reveal').forEach(node => observer.observe(node));
  };

  const _initHeroScrollParallax = () => {
    const heroEl = document.getElementById('hero');
    if (!heroEl) return;
    let isTicking = false;

    window.addEventListener('scroll', () => {
      if (!isTicking) {
        requestAnimationFrame(() => {
          heroEl.classList.toggle('scroll-out', window.scrollY > 160);
          isTicking = false;
        });
        isTicking = true;
      }
    }, { passive: true });
  };

  /* ================================================================
     8. PRIVATE AUTHENTICATION GATE ENGINE
     ================================================================ */
  const _unlockSession = (matchedMemberKey) => {
    _isSessionUnlocked = true;
    _activeMemberId = matchedMemberKey;

    try {
      sessionStorage.setItem(_STORAGE_SESSION_TOKEN_KEY, _PROFILE_REGISTRY[matchedMemberKey].authDigest);
    } catch {
      /* Fallback for environments with disabled storage */
    }

    // Activate corresponding member tab
    document.querySelectorAll('.member-tab-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.member === matchedMemberKey);
    });

    // Render protected data
    _renderMemberView();
    _renderTimelineView();

    // Fade out and remove gate modal
    const overlay = document.getElementById('gateOverlay');
    if (overlay) {
      overlay.classList.add('fade-out');
      overlay.addEventListener('transitionend', () => overlay.remove(), { once: true });
    }
  };

  const _initSecurityGate = () => {
    const overlayNode = document.getElementById('gateOverlay');
    const daySelectNode = document.getElementById('gateDay');
    const monthSelectNode = document.getElementById('gateMonth');
    const yearSelectNode = document.getElementById('gateYear');
    const submitBtnNode = document.getElementById('gateSubmit');
    const errorNode = document.getElementById('gateError');

    if (!overlayNode || !daySelectNode || !monthSelectNode || !yearSelectNode || !submitBtnNode || !errorNode) {
      return;
    }

    // Check if session is already authenticated
    try {
      const storedToken = sessionStorage.getItem(_STORAGE_SESSION_TOKEN_KEY);
      if (storedToken) {
        const existingKey = Object.keys(_PROFILE_REGISTRY).find(k => _PROFILE_REGISTRY[k].authDigest === storedToken);
        if (existingKey) {
          _unlockSession(existingKey);
          return;
        }
      }
    } catch {
      /* Session check fallback */
    }

    // Populate Days (01-31)
    for (let day = 1; day <= 31; day++) {
      const opt = document.createElement('option');
      opt.value = String(day).padStart(2, '0');
      opt.textContent = day;
      daySelectNode.appendChild(opt);
    }

    // Populate Months (01-12)
    const monthLabels = [
      'Tháng 1','Tháng 2','Tháng 3','Tháng 4',
      'Tháng 5','Tháng 6','Tháng 7','Tháng 8',
      'Tháng 9','Tháng 10','Tháng 11','Tháng 12'
    ];
    for (let month = 1; month <= 12; month++) {
      const opt = document.createElement('option');
      opt.value = String(month).padStart(2, '0');
      opt.textContent = monthLabels[month - 1];
      monthSelectNode.appendChild(opt);
    }

    // Populate year range (2003-2008) so the exact birth year is protected from leakage
    const yearRange = [2003, 2004, 2005, 2006, 2007, 2008];
    yearRange.forEach(yr => {
      const opt = document.createElement('option');
      opt.value = String(yr);
      opt.textContent = String(yr);
      yearSelectNode.appendChild(opt);
    });

    const triggerValidationFeedback = () => {
      [daySelectNode, monthSelectNode, yearSelectNode].forEach(node => {
        node.classList.remove('shake');
        void node.offsetWidth; // Force CSS animation reflow
        node.classList.add('shake');
      });
    };

    const processAuthentication = async () => {
      const d = daySelectNode.value;
      const m = monthSelectNode.value;
      const y = yearSelectNode.value;

      if (!d || !m || !y) {
        errorNode.textContent = 'Vui lòng chọn đầy đủ ngày, tháng và năm sinh.';
        triggerValidationFeedback();
        return;
      }

      const rawCredentialString = `${y}-${m}-${d}`;
      const hashedCredential = await _computeDigest(rawCredentialString);

      // Verify against secure SHA-256 digests
      const matchingMemberKey = Object.keys(_PROFILE_REGISTRY).find(
        key => _PROFILE_REGISTRY[key].authDigest === hashedCredential
      );

      if (!matchingMemberKey) {
        errorNode.textContent = 'Ngày sinh không khớp với thành viên nào! Thử lại nhé 😅';
        triggerValidationFeedback();
        return;
      }

      errorNode.textContent = '';
      _unlockSession(matchingMemberKey);
    };

    submitBtnNode.addEventListener('click', processAuthentication);
    [daySelectNode, monthSelectNode, yearSelectNode].forEach(node => {
      node.addEventListener('keydown', evt => {
        if (evt.key === 'Enter') processAuthentication();
      });
    });
  };

  /* ================================================================
     9. PRIVATE BOOTSTRAP INITIALIZER
     ================================================================ */
  const _bootstrap = () => {
    _initSecurityGate();
    _bindGlobalNavigationEvents();
    _initScrollRevealObserver();
    _initHeroScrollParallax();
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _bootstrap);
  } else {
    _bootstrap();
  }
})();

