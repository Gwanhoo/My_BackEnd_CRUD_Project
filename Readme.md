# My Backend CRUD Project

## Realtime Chat (WebSocket)

WebSocket(Socket.IO)을 사용해 사용자 간 실시간 메시지 송수신을 처리합니다.

![chat](./images/chat.png)

- 메시지 실시간 전송/수신
- 채팅방 단위 다중 사용자 통신
- 서버-클라이언트 이벤트 기반 통신(`join-room`, `chat-message`)
- 메시지 DB 저장 후 브로드캐스트

## 프로젝트 개요

커뮤니티 기능(게시글/댓글)과 협업 기능(스터디룸/초대), 실시간 채팅을 통합한 서버 렌더링 기반 서비스입니다.

- 목적: 게시판 중심 서비스에 실시간 대화 기능을 결합해 사용자 상호작용 속도를 높이는 것
- 범위: 인증, 게시글 CRUD, 댓글, 검색, 프로필, 스터디룸, 초대, 실시간 채팅

## 주요 기능

### 인증/계정

- 회원가입/로그인/로그아웃
- 카카오 OAuth 로그인
- 닉네임 설정 및 중복 확인

### 게시판

- 게시글 작성/조회/수정/삭제
- 댓글 작성
- 추천/비추천
- 검색

### 프로필/마이페이지

- 프로필 등록/수정
- 내 글/내 댓글/추천/비추천 목록 조회
- 사용자 목록 조회

### 채팅/스터디룸

- 1:1 채팅방 생성 및 입장
- 채팅방 목록 조회
- 채팅방 이름 변경
- 스터디룸 생성/목록/상세
- 스터디룸 초대/수락

## 스크린샷

### Realtime Chat

![chat](./images/chat.png)

### Studyroom UI

![studyroom](./images/studyroom.png)

### Main UI

![main-ui](./images/main-ui.png)

## 기술 스택

- Frontend: EJS, Tailwind CSS, Vanilla JavaScript
- Backend: Node.js, Express, Passport, express-session
- Database: MongoDB, connect-mongo
- Realtime: Socket.IO

## 아키텍처

본 프로젝트는 REST API + WebSocket 혼합 구조입니다.

- REST API: 인증, 게시글/댓글, 프로필, 스터디룸/초대 같은 일반 요청 처리
- WebSocket: 채팅 메시지 실시간 송수신 처리

### 데이터 흐름 요약

1. 클라이언트가 HTTP 요청으로 페이지와 초기 데이터를 조회
2. 채팅 페이지에서 WebSocket 연결 후 `join-room` 이벤트 전송
3. 사용자가 `chat-message` 이벤트 송신
4. 서버가 메시지를 저장하고 룸 참여자에게 브로드캐스트
5. 클라이언트가 수신 이벤트를 즉시 렌더링

## API 엔드포인트

아래 목록은 현재 코드에 구현된 엔드포인트 기준입니다.

### 인증/사용자

- GET `/register` 회원가입 페이지
- POST `/register` 회원가입 처리
- GET `/login` 로그인 페이지
- POST `/login` 로그인 처리
- GET `/logout` 로그아웃
- GET `/auth/kakao` 카카오 로그인 시작
- GET `/auth/kakao/callback` 카카오 로그인 콜백
- GET `/set-username` 닉네임 설정 페이지
- POST `/set-username` 닉네임 저장
- GET `/check-username` 닉네임 중복 확인

### 게시글/댓글

- GET `/` 메인 페이지
- GET `/list` 게시글 목록
- GET `/list/:N` 게시글 페이지네이션
- GET `/write` 작성 페이지
- POST `/add` 게시글 작성
- GET `/detail/:id` 게시글 상세
- GET `/edit/:id` 수정 페이지
- POST `/edit/:id` 게시글 수정
- DELETE `/delete` 게시글 삭제
- POST `/comment` 댓글 작성
- GET `/search` 검색
- POST `/post/:id/vote` 추천/비추천

### 채팅

- GET `/chat/request` 1:1 채팅방 요청/생성
- GET `/chat/room/:id` 채팅방 입장
- GET `/chat/list` 채팅방 목록
- POST `/chat/room/:id/rename` 채팅방 이름 변경

### 프로필/사람 찾기

- GET `/mypage` 마이페이지
- GET `/profile/edit` 프로필 수정 페이지
- POST `/profile/edit` 프로필 수정
- GET `/people` 사용자 목록

### 스터디룸/초대

- GET `/studyroom/new` 스터디룸 생성 페이지
- POST `/studyroom/new` 스터디룸 생성
- GET `/studyroom/list` 스터디룸 목록
- GET `/studyroom/:id` 스터디룸 상세
- POST `/studyroom/:id/invite` 스터디룸 초대
- GET `/invite/list` 받은 초대 목록
- POST `/invite/accept` 초대 수락
- GET `/invite/search` 초대 대상 검색

### 작성 예정 API

- PATCH `/chat/room/:id` 채팅방 설정 변경 작성 예정
- DELETE `/chat/room/:id` 채팅방 삭제 작성 예정

## 실시간 처리 구조

### WebSocket 연결

- 클라이언트가 채팅 페이지 진입 시 Socket 연결을 생성
- 연결 후 `join-room` 이벤트를 서버로 전송해 룸 참여

### 이벤트 흐름

- Client -> Server: `join-room(roomId)`
- Client -> Server: `chat-message({ roomId, senderId, message })`
- Server -> Clients(in room): `chat-message({ senderId, message })`

### 동기화 방식

- 클라이언트는 송신 즉시 로컬 렌더링(낙관적 표시)
- 서버 브로드캐스트 이벤트로 다른 참여자 화면 동기화
- 페이지 진입 시 서버 렌더링으로 기존 채팅 로그 로드

## 실행 방법

```bash
npm install
npm start
```

CSS 빌드:

```bash
npx postcss ./public/main.css -o ./public/output.css
```

## 트러블슈팅

- Socket 재연결 처리: 작성 예정
- 채팅 메시지 중복 렌더링 방지: 작성 예정
- 세션 만료 시 재인증 흐름: 작성 예정
