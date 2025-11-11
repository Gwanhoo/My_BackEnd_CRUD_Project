const express = require('express');
const app = express();
const { MongoClient, ObjectId } = require('mongodb')
const methodOverride = require('method-override')
const session = require('express-session')
const passport = require('passport')
const LocalStrategy = require('passport-local')
const bcrypt = require('bcrypt') 
const MongoStore = require('connect-mongo')
const { Server } = require('socket.io'); 
require('dotenv').config();
const http = require('http');

const server = http.createServer(app);
const io = new Server(server);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(passport.initialize())
app.use(session({
  secret : process.env.SESSION_SECRET,         
  resave : false,
  saveUninitialized : false,
  cookie: { maxAge : 1000 * 60 * 60 * 2 },
  store : MongoStore.create({
    mongoUrl : process.env.MONGODB_URI,          
    dbName   : process.env.MONGODB_DB_NAME       
  })
}));


app.use(passport.session())

app.use(methodOverride('_method'))
app.use(express.static(__dirname + '/public'));
app.set('view engine', 'ejs');

let db;
const url = process.env.MONGODB_URI;              
new MongoClient(url).connect()
  .then((client) => {
    console.log('DB연결성공');
    db = client.db(process.env.MONGODB_DB_NAME);  
  })
  .catch((err) => {
    console.error('[DB ERROR]', err);
  });



app.use((요청, 응답, next) => {
  응답.locals.isLogin = 요청.isAuthenticated && 요청.isAuthenticated();
  응답.locals.user = 요청.user; // 로그인 되어 있으면 사용자 정보
  next();
});

function 로그인확인(요청, 응답, next) {
  if (요청.isAuthenticated && 요청.isAuthenticated()) return next();
  // 비로그인 → 로그인 페이지로
  return 응답.redirect('/login');
}

function 작성자확인(컬렉션명 = 'post') {
  return async (요청, 응답, next) => {
    try {
      // id는 /edit/:id 처럼 params거나, /delete?docId= 처럼 query일 수 있음
      const rawId = 요청.params.id || 요청.query.docId;
      if (!rawId) return 응답.status(400).send('글 ID가 없습니다.');

      const _id = new ObjectId(rawId);
      const post = await db.collection(컬렉션명).findOne({ _id });
      if (!post) return 응답.status(404).send('게시글을 찾을 수 없습니다.');

      // 작성자 비교
      const 작성자 = post.authorId?.toString?.() || String(post.authorId);
      const 로그인유저 = 요청.user?._id?.toString?.();
      if (!로그인유저 || 작성자 !== 로그인유저) {
        return 응답.status(403).send('권한이 없습니다.');
      }

      // 다음 핸들러에서 재조회 안 하도록 보관
      요청.post = post;
      return next();
    } catch (e) {
      console.error(e);
      return 응답.status(400).send('잘못된 요청입니다.');
    }
  };
}


// app.listen(8080, () => {
//     console.log("http://localhost:8080 에서 서버 실행중");

// })

server.listen(8080, () => {
  console.log('http://localhost:8080 에서 서버 실행중');
});

app.get('/', (요청, 응답) => {
    응답.render('index.ejs')
})


app.get('/list', async (요청, 응답) => {
    let result = await db.collection('post').find().toArray()
    응답.render('list.ejs', { posts : result})
})


app.get('/write', 로그인확인, (요청, 응답) => {
  응답.render('write.ejs');
});

function parseTags(tagString) {
  if (!tagString) return [];

  const regex = /#([\p{L}\p{N}._-]{1,30})/gu; // 유니코드 문자/숫자 + . _ - 허용
  const matches = [...tagString.matchAll(regex)];
  let tags = matches.map(m => m[1]);

  // 중복 제거(대소문자 무시), 공백/빈값 제거
  const seen = new Set();
  tags = tags.filter(t => {
    const key = t.toLowerCase();
    if (!t || seen.has(key)) return false;
    seen.add(key);
    return true;
  });


  if (tags.length > 10) tags = tags.slice(0, 10);

  return tags;
}

app.post('/add', 로그인확인, async (요청, 응답) => {
  try {
    const title = (요청.body.title || '').trim();
    const content = (요청.body.content || '').trim();
    const rawTags = 요청.body.tags || '';

    if (!title)   return 응답.status(400).send('제목을 입력하세요.');
    if (!content) return 응답.status(400).send('내용을 입력하세요.');
    if (!요청.user) return 응답.status(401).send('로그인이 필요합니다.');


    const tags = parseTags(rawTags);
    const tags_lc = tags.map(t => t.toLowerCase()); // 검색용(대소문자 무시)

    const doc = {
      title,
      content,
      tags,                 // 표시용 태그(원본 케이스 유지)
      tags_lc,              // 검색 최적화용 소문자 태그
      authorId: 요청.user._id,
      authorName: 요청.user.username,
      createdAt: new Date(),
    };

    await db.collection('post').insertOne(doc);
    return 응답.redirect('/list');
  } catch (err) {
    console.error('POST /add error:', err);
    return 응답.status(500).send('서버 오류가 발생했습니다.');
  }
});

app.get('/detail/:id', async (요청, 응답) => {
  
  let result1 = await db.collection('comment').find({parentId : new ObjectId(요청.params.id)}).toArray()

  let result = await db.collection('post').findOne({_id : new ObjectId
      (요청.params.id)})
  응답.render('detail.ejs', { result : result, result1 : result1 });

})

app.get('/edit/:id', 로그인확인, 작성자확인('post'), async (요청, 응답) => {
  응답.render('edit.ejs', { post: 요청.post });
});

app.post('/edit/:id', 로그인확인, 작성자확인('post'), async (요청, 응답) => {
  const { title, content } = 요청.body;
  await db.collection('post').updateOne(
    { _id: 요청.post._id },
    { $set: { title, content } }
  );
  응답.redirect('/detail/' + 요청.post._id);
});

app.delete('/delete', 로그인확인, 작성자확인('post'), async (요청, 응답) => {
  await db.collection('post').deleteOne({ _id: 요청.post._id });
  응답.send('삭제완료');
});

app.get('/list/:N', async (요청, 응답) => {
    let N = parseInt(요청.params.N)

    if (isNaN(N) || N < 1) {
        N = 1; 
    }


    let result = await db.collection('post').find().skip((N-1)*5).limit(5).toArray()
    응답.render('list.ejs', { posts : result})
})

app.get('/register', (요청, 응답) => {
  응답.render('register.ejs');
});

app.post('/register', async (요청, 응답) => {
  try {
    const { username, password } = 요청.body;

    // 입력값 검증
    if (!username || !password) {
      return 응답.status(400).send('아이디와 비밀번호를 입력해주세요.');
    }

    // 기존 사용자 존재 여부 확인
    const exists = await db.collection('user').findOne({ username });
    if (exists) {
      return 응답.status(409).send('이미 존재하는 아이디입니다.');
    }

    // 비밀번호 해싱
    const 해시 = await bcrypt.hash(password, 10);

    // 해시 저장 (중요!)
    await db.collection('user').insertOne({ username, password: 해시 });

    return 응답.redirect('/login');
  } catch (에러) {
    console.error('회원가입 중 에러 발생:', 에러);

    // 중복키 에러(유니크 인덱스가 있다면) 처리
    if (에러?.code === 11000) {
      return 응답.status(409).send('이미 존재하는 아이디입니다.');
    }
    return 응답.status(500).send('서버 내부 에러가 발생했습니다. 잠시 후 다시 시도해주세요.');
  }
});



passport.use(new LocalStrategy(
  // 기본 필드 이름이 username/password라면 옵션 생략 가능
  async (입력한아이디, 입력한비번, cb) => {
    try {
      const user = await db.collection('user').findOne({ username: 입력한아이디 });
      if (!user) return cb(null, false, { message: '아이디 DB에 없음' });

      const ok = await bcrypt.compare(입력한비번, user.password);
      if (!ok) return cb(null, false, { message: '비번불일치' });

      return cb(null, user);
    } catch (e) {
      return cb(e);
    }
  }
));

passport.serializeUser((user, done) => {
  process.nextTick(() => {
    done(null, { id: user._id.toString(), username: user.username }); // 문자열로!
  });
});

passport.deserializeUser(async (user, done) => {
  try {
    const result = await db.collection('user').findOne({ _id: new ObjectId(user.id) });
    if (!result) return done(null, false); // 사용자 삭제된 경우 등
    delete result.password; // 민감정보 제거
    process.nextTick(() => done(null, result));
  } catch (e) {
    done(e);
  }
});

app.get('/login', (요청, 응답) => {
  // 아직 로그인 전이면 요청.user는 undefined일 수 있음
  응답.render('login.ejs');
});

app.post('/login', (요청, 응답, next) => {
  passport.authenticate('local', (error, user, info) => {
    if (error) return 응답.status(500).json(error);
    if (!user) return 응답.status(401).json(info?.message || '로그인 실패');

    요청.logIn(user, (err) => {
      if (err) return next(err);
      return 응답.redirect('/');
    });
  })(요청, 응답, next);
});


app.get('/mypage', 로그인확인, async (요청, 응답) => {
  try {
    const me = 요청.user;
    const meId = new ObjectId(me._id);
    const myPosts = await db.collection('post')
      .find({ authorId: meId })
      .sort({ createdAt: -1 })
      .toArray();

    응답.render('mypage.ejs', { me, myPosts });
  } catch (e) {
    console.error(e);
    응답.status(500).send('서버 에러');
  }
});

app.get('/logout', (요청, 응답, next) => {
  요청.logout(function (err) {
    if (err) { return next(err); }
    응답.redirect('/'); // 로그아웃 후 메인 페이지로 이동
  });
});

app.post('/comment', 로그인확인, async (요청, 응답) => {
  const content = 요청.body.content?.trim();
  if (!content) {
    return 응답.status(400).send('<script>alert("댓글을 입력해주세요."); history.back();</script>');
  }
  
  await db.collection('comment').insertOne({
    parentId: new ObjectId(요청.body.parentId),
    content: 요청.body.content,
    authorId: 요청.user._id,
    authorName: 요청.user.username,
    createdAt: new Date(),
  })
  응답.redirect('/detail/' + 요청.body.parentId);
});


// 특수문자 이스케이프 (사용자 입력을 안전한 정규식 리터럴로)
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

app.get('/search', async (req, res) => {
  //  기존 파라미터 'val' 유지 + 링크에서 'keyword'로 넘어와도 허용
  const raw = (req.query.val ?? req.query.keyword ?? '').toString().trim();

  if (!raw) {
    return res.send(`<script>alert('검색어를 입력하세요'); history.back();</script>`);
  }

  const isTag = raw.startsWith('#');
  let query;

  if (isTag) {
    //  #태그 검색: tags_lc 완전일치
    const tag = raw.slice(1).toLowerCase();
    query = { tags_lc: tag };
  } else {
    //  일반 검색: 제목(공백무시) OR 내용 OR 태그명(대소문자무시)
    const escaped = escapeRegex(raw);
    const noSpace = escaped.replace(/\s+/g, ''); // "노 드" → "노드"

    query = {
      $or: [
        // 제목: 공백 제거 후 정규식 매칭 (네 코드 유지)
        {
          $expr: {
            $regexMatch: {
              input: { $replaceAll: { input: "$title", find: " ", replacement: "" } },
              regex: noSpace,
              options: "i"
            }
          }
        },
        // 내용: 단순 부분 일치
        { content: { $regex: escaped, $options: "i" } },
        // 태그: 정확히 같은 단어일 때도 매칭
        { tags_lc: raw.toLowerCase() }
      ]
    };
  }

  const posts = await db.collection('post').find(query).toArray();

  if (posts.length === 0) {
    return res.send(`<script>alert('검색 결과 없음'); history.back();</script>`);
  }

  const isLogin = !!req.user;
  const user = req.user || null;
  return res.render('search', { posts, q: raw, isLogin, user });
});

app.get("/chat/request", 로그인확인, async (req, res) => {
  // writerId, writer_id 둘 다 받아줌 (앞에서 이름을 섞어썼으니까)
  const targetIdRaw = req.query.writerId || req.query.writer_id;
  if (!targetIdRaw) {
    return res.status(400).send("채팅할 대상이 없습니다.");
  }

  const me = req.user._id;
  const targetId = new ObjectId(targetIdRaw);

  // ✅ 자기 자신과는 채팅방 만들지 않기
  if (String(me) === String(targetId)) {
    return res.send("<script>alert('자기 자신과는 채팅할 수 없습니다.'); history.back();</script>");
  }

  // ✅ 이미 방 있는지 확인
  const existingRoom = await db.collection("chatroom").findOne({
    member: { $all: [me, targetId] }
  });

  if (existingRoom) {
    return res.redirect(`/chat/room/${existingRoom._id}`);
  }

  // ✅ 없으면 새로 생성
  const result = await db.collection("chatroom").insertOne({
    member: [me, targetId],
    date: new Date()
  });

  return res.redirect(`/chat/room/${result.insertedId}`);
});

app.get("/chat/room/:id", 로그인확인, async (req, res) => {
  const roomId = req.params.id;

  const room = await db.collection("chatroom").findOne({
    _id: new ObjectId(roomId),
    member: req.user._id
  });

  if (!room) {
    return res.status(404).send("채팅방을 찾을 수 없습니다.");
  }

  // 기존 메시지 불러오기 (선택 사항)
  const messages = await db.collection("messages")
    .find({ roomId: new ObjectId(roomId) })
    .sort({ date: 1 })
    .toArray();

  res.render("chatRoom.ejs", {
    room,
    messages,
    user: req.user
  });
});

app.get("/chat/list", 로그인확인, async(요청, 응답) => {
  let chatrooms = await db.collection('chatroom').find({ member : 요청.user._id}).toArray()
  응답.render('chatList.ejs', { chatrooms : chatrooms})
});

// 프로필 작성 화면
app.get('/profile/edit', 로그인확인, async (req, res) => {
  const userId = req.user._id;
  const profile = await db.collection('people').findOne({ userId: userId });
  res.render('profileEdit.ejs', { me: req.user, profile });
});

// 프로필 저장
app.post('/profile/edit', 로그인확인, async (req, res) => {
  const userId = req.user._id;

  const data = {
    userId: userId,
    name: req.body.name,
    age: req.body.age ? Number(req.body.age) : null,
    school: req.body.school,
    hobby: req.body.hobby,
    intro: req.body.intro,
    stacks: req.body.stacks
      ? req.body.stacks.split(',').map(s => s.trim()).filter(Boolean)
      : [],
    updatedAt: new Date()
  };

  const exist = await db.collection('people').findOne({ userId: userId });

  if (exist) {
    await db.collection('people').updateOne(
      { userId: userId },
      { $set: data }
    );
  } else {
    data.createdAt = new Date();
    await db.collection('people').insertOne(data);
  }

  res.redirect('/people'); // 저장 후 사람 목록으로 보내거나 /mypage 로 보내도 됨
});

// 📍 people 목록 조회
app.get("/people", async (req, res) => {
  try {
    const people = await db.collection("people")
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    res.render("people.ejs", { people });
  } catch (err) {
    console.error(err);
    res.status(500).send("프로필 목록을 불러오는 중 오류가 발생했습니다.");
  }
});

io.on('connection', (socket) => {
  console.log('🟢 socket connected :', socket.id);

  // 방 입장
  socket.on('join-room', (roomId) => {
    socket.join(roomId);
    console.log('room joined:', roomId);
  });

  // 메시지 받기
  socket.on('chat-message', async (data) => {
    console.log('💬 받은 메시지:', data);

    await db.collection('messages').insertOne({
      roomId: new ObjectId(data.roomId),
      senderId: new ObjectId(data.senderId),
      message: data.message,
      date: new Date()
    });

    // 나 빼고 같은 방 사람한테만 방송
    socket.to(data.roomId).emit('chat-message', data);
  });
});
