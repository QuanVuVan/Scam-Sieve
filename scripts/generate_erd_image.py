import os
from PIL import Image, ImageDraw, ImageFont

def create_erd():
    W, H = 2400, 1550
    img = Image.new("RGB", (W, H), "#F8FAFC")
    draw = ImageDraw.Draw(img)

    # Load Windows fonts
    font_path_bold = r"C:\Windows\Fonts\segoeuib.ttf"
    font_path_reg = r"C:\Windows\Fonts\segoeui.ttf"
    font_path_semi = r"C:\Windows\Fonts\seguisb.ttf"
    font_path_mono = r"C:\Windows\Fonts\consola.ttf"

    title_font = ImageFont.truetype(font_path_bold, 40)
    subtitle_font = ImageFont.truetype(font_path_reg, 22)
    tbl_title_font = ImageFont.truetype(font_path_bold, 24)
    tbl_desc_font = ImageFont.truetype(font_path_reg, 17)
    col_name_font = ImageFont.truetype(font_path_semi, 19)
    col_type_font = ImageFont.truetype(font_path_mono, 17)
    badge_font = ImageFont.truetype(font_path_bold, 15)
    rel_font = ImageFont.truetype(font_path_bold, 18)

    # 1. Header Title
    draw.text((W // 2, 50), "SƠ ĐỒ THỰC THỂ - LIÊN KẾT (ERD) - HỆ THỐNG P-SIEVE", font=title_font, fill="#0F172A", anchor="mt")
    draw.text((W // 2, 105), "Mô hình Cơ sở dữ liệu Quan hệ chuẩn hoá (SQLAlchemy 2.0 ORM - SQLite / PostgreSQL)", font=subtitle_font, fill="#64748B", anchor="mt")

    # Helper function to draw a table box
    def draw_table(x, y, w, title, desc, columns, header_bg="#1E3A8A"):
        row_h = 42
        header_h = 70
        total_h = header_h + len(columns) * row_h + 16

        # Drop shadow
        draw.rounded_rectangle([x + 6, y + 6, x + w + 6, y + total_h + 6], radius=14, fill="#E2E8F0")
        # Main card background
        draw.rounded_rectangle([x, y, x + w, y + total_h], radius=14, fill="#FFFFFF", outline="#CBD5E1", width=2)
        # Header background
        draw.rounded_rectangle([x, y, x + w, y + header_h], radius=14, fill=header_bg)
        # Square off bottom of header
        draw.rectangle([x, y + header_h - 14, x + w, y + header_h], fill=header_bg)

        # Header Text
        draw.text((x + 20, y + 16), title, font=tbl_title_font, fill="#FFFFFF")
        draw.text((x + 20, y + 43), desc, font=tbl_desc_font, fill="#93C5FD")

        # Columns
        curr_y = y + header_h + 8
        for i, col in enumerate(columns):
            name, dtype, tag = col
            # Alternating subtle row color
            if i % 2 == 1:
                draw.rectangle([x + 2, curr_y, x + w - 2, curr_y + row_h], fill="#F8FAFC")

            # Column Name
            name_color = "#0F172A"
            draw.text((x + 20, curr_y + 10), name, font=col_name_font, fill=name_color)

            # Data Type
            draw.text((x + 230, curr_y + 12), dtype, font=col_type_font, fill="#475569")

            # Badge / Constraints
            if tag:
                badge_bg = "#E0E7FF"
                badge_fg = "#3730A3"
                if "PK" in tag:
                    badge_bg = "#FEF3C7"
                    badge_fg = "#92400E"
                elif "FK" in tag:
                    badge_bg = "#DBEAFE"
                    badge_fg = "#1E40AF"
                elif "Nullable" in tag:
                    badge_bg = "#F1F5F9"
                    badge_fg = "#64748B"
                elif "Unique" in tag:
                    badge_bg = "#DCFCE7"
                    badge_fg = "#166534"

                bx = x + w - 145
                by = curr_y + 8
                draw.rounded_rectangle([bx, by, bx + 125, by + 26], radius=6, fill=badge_bg)
                draw.text((bx + 62, by + 5), tag, font=badge_font, fill=badge_fg, anchor="mt")

            curr_y += row_h

        return x, y, w, total_h

    # Table Definitions
    users_cols = [
        ("id", "Integer", "PK"),
        ("email", "String(255)", "Unique"),
        ("hashed_password", "String(255)", "Not Null"),
        ("full_name", "String(100)", "Nullable"),
        ("role", "Enum(UserRole)", "user / admin"),
        ("is_active", "Boolean", "Default True"),
        ("created_at", "DateTime", "Not Null")
    ]

    scan_cols = [
        ("id", "Integer", "PK"),
        ("user_id", "Integer", "FK -> users.id"),
        ("input_type", "Enum(InputType)", "text/url/phone..."),
        ("original_content", "Text", "Nullable (Privacy)"),
        ("risk_score", "Integer (0-100)", "Not Null"),
        ("risk_level", "Enum(RiskLevel)", "LOW/MED/HIGH"),
        ("matched_rules", "JSON", "Not Null"),
        ("created_at", "DateTime", "Not Null")
    ]

    report_cols = [
        ("id", "Integer", "PK"),
        ("reporter_id", "Integer", "FK -> users.id (N)"),
        ("reporter_ip", "String(45)", "Nullable"),
        ("content_type", "Enum(ContentType)", "url/phone/text..."),
        ("content", "Text", "Not Null"),
        ("reporter_note", "Text", "Nullable"),
        ("status", "Enum(ReportStatus)", "PENDING/APP/REJ"),
        ("reviewed_by_id", "Integer", "FK -> users.id (N)"),
        ("reviewed_at", "DateTime", "Nullable"),
        ("admin_note", "Text", "Nullable"),
        ("created_at", "DateTime", "Not Null")
    ]

    blacklist_cols = [
        ("id", "Integer", "PK"),
        ("content_type", "Enum(ContentType)", "phone/url/bank..."),
        ("value", "String(255)", "Indexed, Not Null"),
        ("note", "Text", "Nullable"),
        ("source", "String(255)", "Nullable"),
        ("source_report_id", "Integer", "FK -> reports.id (N)"),
        ("created_by_admin_id", "Integer", "FK -> users.id (N)"),
        ("created_at", "DateTime", "Not Null")
    ]

    # Render 4 Tables
    # Col 1: Users (top-left) & Reports (bottom-left)
    # Col 2: ScanHistory (top-right) & Blacklist (bottom-right)
    u_x, u_y, u_w, u_h = draw_table(120, 180, 540, "users", "Bảng tài khoản & phân quyền", users_cols, header_bg="#1E3A8A")
    s_x, s_y, s_w, s_h = draw_table(1380, 180, 580, "scan_history", "Bảng lịch sử quét rủi ro", scan_cols, header_bg="#0D9488")
    r_x, r_y, r_w, r_h = draw_table(120, 680, 580, "reports", "Bảng báo cáo lừa đảo cộng đồng", report_cols, header_bg="#4338CA")
    b_x, b_y, b_w, b_h = draw_table(1380, 680, 600, "blacklist", "Bảng danh sách đen tập trung", blacklist_cols, header_bg="#B91C1C")

    # Draw Relation Lines with Arrows & Labels
    line_color = "#334155"
    lw = 4

    # 1. users (1) -> scan_history (N)
    # Start: (u_x + u_w, 230) -> End: (s_x, 230)
    p1 = (u_x + u_w, 230)
    p2 = (s_x, 230)
    draw.line([p1, p2], fill=line_color, width=lw)
    # End arrow on scan_history
    draw.polygon([(s_x, 230), (s_x - 14, 222), (s_x - 14, 238)], fill=line_color)
    # Labels
    draw.text((p1[0] + 15, 200), "1", font=rel_font, fill="#1E3A8A")
    draw.text((p2[0] - 35, 200), "N", font=rel_font, fill="#0D9488")
    draw.rounded_rectangle([(p1[0] + p2[0]) // 2 - 140, 205, (p1[0] + p2[0]) // 2 + 140, 255], radius=8, fill="#FFFFFF", outline="#94A3B8", width=2)
    draw.text(((p1[0] + p2[0]) // 2, 218), "Thực hiện lượt quét (user_id)", font=rel_font, fill="#1E293B", anchor="mt")

    # 2. users (1) -> reports (N) [reporter_id & reviewed_by_id]
    # Line from bottom of users (u_x + 200, u_y + u_h) down to top of reports (r_x + 200, r_y)
    p_u_down = (u_x + 240, u_y + u_h)
    p_r_up = (r_x + 240, r_y)
    draw.line([p_u_down, p_r_up], fill=line_color, width=lw)
    draw.polygon([(p_r_up[0], p_r_up[1]), (p_r_up[0] - 8, p_r_up[1] - 14), (p_r_up[0] + 8, p_r_up[1] - 14)], fill=line_color)
    draw.text((p_u_down[0] + 15, p_u_down[1] + 10), "1", font=rel_font, fill="#1E3A8A")
    draw.text((p_r_up[0] + 15, p_r_up[1] - 35), "N", font=rel_font, fill="#4338CA")
    draw.rounded_rectangle([p_u_down[0] + 15, (p_u_down[1] + p_r_up[1]) // 2 - 25, p_u_down[0] + 310, (p_u_down[1] + p_r_up[1]) // 2 + 25], radius=8, fill="#FFFFFF", outline="#94A3B8", width=2)
    draw.text((p_u_down[0] + 162, (p_u_down[1] + p_r_up[1]) // 2 - 12), "Gửi / Duyệt báo cáo", font=rel_font, fill="#1E293B", anchor="mt")

    # 3. reports (1) -> blacklist (0..1) [source_report_id]
    # Start: (r_x + r_w, 820) -> End: (b_x, 820)
    p_r_right = (r_x + r_w, 820)
    p_b_left = (b_x, 820)
    draw.line([p_r_right, p_b_left], fill=line_color, width=lw)
    draw.polygon([(p_b_left[0], 820), (p_b_left[0] - 14, 812), (p_b_left[0] - 14, 828)], fill=line_color)
    draw.text((p_r_right[0] + 15, 790), "1", font=rel_font, fill="#4338CA")
    draw.text((p_b_left[0] - 65, 790), "0..1", font=rel_font, fill="#B91C1C")
    draw.rounded_rectangle([(p_r_right[0] + p_b_left[0]) // 2 - 170, 795, (p_r_right[0] + p_b_left[0]) // 2 + 170, 845], radius=8, fill="#FFFFFF", outline="#94A3B8", width=2)
    draw.text(((p_r_right[0] + p_b_left[0]) // 2, 808), "Tạo Blacklist khi duyệt (source_report_id)", font=rel_font, fill="#1E293B", anchor="mt")

    # Footer note
    footer_text = "Ghi chú: PK = Primary Key (Khóa chính) | FK = Foreign Key (Khóa ngoại) | (N) = Nullable (Cho phép rỗng để bảo vệ quyền riêng tư & báo cáo ẩn danh)"
    draw.text((W // 2, H - 45), footer_text, font=subtitle_font, fill="#64748B", anchor="mt")

    # Save to docs and root
    os.makedirs(r"c:\Users\Admin\Downloads\Project\docs", exist_ok=True)
    out_path = r"c:\Users\Admin\Downloads\Project\docs\erd_database_diagram.png"
    img.save(out_path, format="PNG", dpi=(300, 300))
    print("ERD image successfully created at:", out_path)

if __name__ == "__main__":
    create_erd()

