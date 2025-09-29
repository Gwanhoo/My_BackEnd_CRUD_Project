# 코딩애플 백엔드 프로젝트

Node.js + Express + MongoDB 기반의 간단한 게시판 및 회원 관리 기능 구현 프로젝트입니다. 포트폴리오 제출용으로 제작되었습니다.

---

## 🧠 사용 기술 스택

* **Runtime**: Node.js
* **Framework**: Express.js
* **Database**: MongoDB (Atlas)
* **Template Engine**: EJS
* **Authentication**: Passport Local, express-session
* **Hashing**: bcrypt
* **Environment Management**: dotenv
* **Session Store**: connect-mongo
* **CSS Framework**: Tailwind CSS (PostCSS 구성)

---

## ✨ 주요 기능

* 회원가입 / 로그인 / 로그아웃
* 게시글 CRUD (생성, 읽기, 수정, 삭제)
* 댓글 기능
* 마이페이지 (본인 게시글 관리)
* 작성자 인증 (본인만 수정/삭제 가능)

> ⚠️ 좋아요 / 싫어요(추천/비추천) 기능 및 게시글 검색 기능은 **미구현 상태**입니다.

---

## 📁 디렉터리 구조

```
project-root/
├─ node_modules/
├─ public/                  # 정적 파일(css, js)
│  ├─ input.css
│  ├─ main.css
│  └─ output.css
├─ views/                   # EJS 템플릿 파일
│  ├─ detail.ejs
│  ├─ edit.ejs
│  ├─ index.ejs
│  ├─ list.ejs
│  ├─ login.ejs
│  ├─ mypage.ejs
│  ├─ nav.ejs
│  ├─ register.ejs
│  └─ write.ejs
├─ .env                     # 환경 변수 (비공개)
├─ package.json
├─ package-lock.json
├─ postcss.config.js        # Tailwind/PostCSS 설정
├─ tailwind.config.js       # Tailwind 설정
├─ server.js                # 서버 진입점
└─ Readme.md                # 프로젝트 문서
```

---

## 📡 API 엔드포인트 요약

| Method | Endpoint      | 설명                  |
| :----: | :------------ | :------------------ |
|   GET  | `/list`       | 게시글 목록 페이지          |
|   GET  | `/detail/:id` | 게시글 상세 페이지          |
|   GET  | `/write`      | 게시글 작성 페이지 (로그인 필요) |
|  POST  | `/write`      | 게시글 작성 처리           |
|   GET  | `/edit/:id`   | 게시글 수정 페이지 (작성자만)   |
|  POST  | `/edit/:id`   | 게시글 수정 처리           |
|  POST  | `/delete/:id` | 게시글 삭제 (작성자만)       |
|  POST  | `/comment`    | 댓글 작성               |

> 🚧 좋아요/싫어요(`like`, `dislike`) 및 게시글 검색(`/search`) 관련 API는 현재 **미구현**입니다.

### 🎨 디자인 관련 안내

> 이 프로젝트는 **백엔드 로직 및 기능 구현 연습용**으로 제작되었습니다.  
> UI/UX 디자인 작업은 포함되어 있지 않으며, **GPT 제안 코드** 또는 **Tailwind 기본 스타일**만 사용했습니다.  
> 별도의 **Figma 시안**이나 **커스텀 CSS 디자인 작업**은 진행하지 않았습니다.


## 🚀 향후 개선 계획
- 게시글 검색 기능 추가
- 좋아요/싫어요 기능 구현
- 조회수 기능 추가