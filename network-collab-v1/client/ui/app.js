/* Browser UI for chat, file transfer and connection status.
 * CollaborationClient owns the network protocol; this UI talks to the local HTTP bridge.
 */
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const MAX_BYTES = 1000;
  const MAX_MESSAGES_PER_THREAD = 200;
  const encoder = new TextEncoder();
  let token = null;
  let cursor = 0;
  let state = 'disconnected';
  let bridgeReachable = false;
  let me = null;
  let busy = false;
  let polling = false;
  let sending = false;
  let activeChat = 'global';
  let onlineUsers = [];
  const threads = new Map();
  const unread = new Map();
  const pending = new Map();
  const earlyReceipts = new Map();
  const seenServerMessages = new Set();
  const files = new Map();
  const fileRequests = new Map();
  const MAX_FILE = 50 * 1024 * 1024;
  let batch = [];
  let offeringFile = false;

  const node = (tag, cls, content) => {
    const item = document.createElement(tag);
    if (cls) item.className = cls;
    if (content !== undefined) item.textContent = String(content);
    return item;
  };
  const initials = (name) =>
    name ? Array.from(name)[0].toLocaleUpperCase('vi') : '?';
  const keyFor = (name) => (name === 'global' ? 'global' : `dm:${name}`);
  const messagesIn = (key) => {
    if (!threads.has(key)) threads.set(key, []);
    return threads.get(key);
  };
  function remember(key, message) {
    const list = messagesIn(key);
    list.push(message);
    if (list.length > MAX_MESSAGES_PER_THREAD) list.shift();
    if (key !== activeChat) unread.set(key, (unread.get(key) || 0) + 1);
    if (key === activeChat) renderMessages();
    renderContacts();
  }
  function resetChat() {
    threads.clear();
    unread.clear();
    pending.clear();
    earlyReceipts.clear();
    seenServerMessages.clear();
    activeChat = 'global';
    onlineUsers = [];
    batch = [];
    files.clear();
    fileRequests.clear();
    offeringFile = false;
    $('fileInput').value = '';
    $('messageInput').value = '';
    $('contactSearch').value = '';
    $('chatNotice').hidden = true;
    renderContacts();
    renderMessages();
    renderChannel();
    renderFiles();
  }
  async function request(path, { method = 'GET', payload } = {}) {
    const options = { method, cache: 'no-store', headers: {} };
    if (payload !== undefined) {
      options.headers['Content-Type'] = 'application/json';
      options.headers['X-Bridge-Token'] = token;
      options.body = JSON.stringify(payload);
    }
    const response = await fetch(path, options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
    return data;
  }
  function setResilienceBanner(kind, details = '') {
    const bar = $('resilienceBanner');
    const lost = kind === 'bridge';
    bar.hidden = !kind;
    bar.classList.toggle('bridge-lost', lost);
    $('resilienceTitle').textContent = lost
      ? 'Không liên hệ được HTTP Bridge'
      : 'Phiên kết nối đã bị gián đoạn';
    $('resilienceMessage').textContent =
      details ||
      (lost
        ? 'Ứng dụng trên localhost đang không phản hồi. Đang kiểm tra lại; không gửi lại lệnh tự động.'
        : 'Server đã ngắt kết nối. Cần đăng nhập lại; tin nhắn/file chưa được xác nhận có thể chưa hoàn tất.');
    $('retryBridgeButton').textContent = 'Kiểm tra lại';
  }
  function refreshAvailability() {
    const usable = state === 'online' && bridgeReachable;
    $('messageInput').readOnly = !usable;
    $('fileInput').disabled = !usable || offeringFile;
    $('fileRecipient').disabled = !usable || offeringFile;
    updateBytes();
    updateFileRecipients();
  }
  function notice(message, error = false) {
    const bar = $('chatNotice');
    bar.hidden = !message;
    bar.textContent = message || '';
    bar.classList.toggle('notice-error', error);
  }
  function loginError(message) {
    $('formError').hidden = !message;
    $('formError').textContent = message || '';
  }
  function renderChannel() {
    const global = activeChat === 'global';
    const name = global ? 'Global Chat' : activeChat.slice(3);
    const isOnline = onlineUsers.includes(name);
    $('channelIcon').textContent = global ? '#' : initials(name);
    $('channelEyebrow').textContent = global
      ? 'KÊNH CHUNG'
      : 'TIN NHẮN TRỰC TIẾP';
    $('channelTitle').textContent = name;
    $('channelSubtitle').textContent = global
      ? 'Trò chuyện cùng tất cả thành viên đang online'
      : isOnline
        ? `${name} đang trực tuyến`
        : `${name} hiện không trực tuyến`;
    $('chatMemberCount').textContent = global
      ? `${onlineUsers.length} thành viên`
      : isOnline
        ? 'Đang online'
        : 'Offline';
    $('messageInput').placeholder = global
      ? 'Nhắn cho cả nhóm...'
      : `Nhắn riêng cho ${name}...`;
    $('sendButton').disabled =
      state !== 'online' ||
      !bridgeReachable ||
      sending ||
      (!global && !isOnline);
    $('globalChatButton').classList.toggle('selected', global);
    $('globalChatButton').setAttribute(
      'aria-current',
      global ? 'page' : 'false',
    );
    const badge = $('globalUnread');
    badge.textContent = String(unread.get('global') || 0);
    badge.hidden = !(unread.get('global') || 0);
  }
  function renderContacts() {
    const holder = $('membersList');
    holder.replaceChildren();
    const filter = $('contactSearch').value.trim().toLocaleLowerCase('vi');
    const names = new Set([
      ...onlineUsers.filter((u) => u !== me),
      ...Array.from(threads.keys())
        .filter((k) => k.startsWith('dm:'))
        .map((k) => k.slice(3)),
    ]);
    const contacts = Array.from(names)
      .filter((name) => name.toLocaleLowerCase('vi').includes(filter))
      .sort(
        (a, b) =>
          Number(onlineUsers.includes(b)) - Number(onlineUsers.includes(a)) ||
          a.localeCompare(b),
      );
    if (!contacts.length) {
      holder.append(
        node(
          'div',
          'empty-members',
          filter
            ? 'Không tìm thấy thành viên'
            : 'Chưa có thành viên khác online',
        ),
      );
    }
    for (const name of contacts) {
      const key = keyFor(name);
      const item = node(
        'button',
        'contact-button' + (activeChat === key ? ' selected' : ''),
      );
      item.type = 'button';
      item.setAttribute('aria-label', `Trò chuyện với ${name}`);
      const avatar = node('span', 'member-avatar', initials(name));
      const detail = node('span', 'contact-detail');
      detail.append(node('strong', null, name));
      detail.append(
        node(
          'small',
          null,
          onlineUsers.includes(name) ? '● Đang online' : '○ Offline',
        ),
      );
      item.append(avatar, detail);
      if (unread.get(key))
        item.append(
          node('span', 'unread-badge', Math.min(99, unread.get(key))),
        );
      item.addEventListener('click', () => selectChat(key));
      holder.append(item);
    }
    $('onlineCount').textContent = String(onlineUsers.length);
    $('statOnline').textContent = String(onlineUsers.length);
    renderChannel();
    updateFileRecipients();
  }
  function selectChat(key) {
    activeChat = key;
    unread.delete(key);
    renderContacts();
    renderMessages();
    $('messageInput').focus();
  }
  function clock(ts) {
    return new Date(ts || Date.now()).toLocaleTimeString('vi-VN', {
      hour: '2-digit',
      minute: '2-digit',
    });
  }
  function renderMessages() {
    const holder = $('messageList');
    const nearBottom =
      holder.scrollHeight - holder.scrollTop - holder.clientHeight < 120;
    holder.replaceChildren();
    const current = messagesIn(activeChat);
    if (!current.length) {
      const empty = node('div', 'chat-empty');
      empty.append(
        node('span', 'chat-empty-icon', '✦'),
        node(
          'strong',
          null,
          activeChat === 'global'
            ? 'Chào mừng đến Global Chat'
            : 'Bắt đầu một cuộc trò chuyện',
        ),
        node(
          'p',
          null,
          'Tin nhắn xuất hiện tại đây khi được nhận trong phiên hiện tại.',
        ),
      );
      holder.append(empty);
      return;
    }
    for (const message of current) {
      const own = message.from === me;
      const row = node('div', `message-row${own ? ' my-message' : ''}`);
      const avatar = node('div', 'msg-avatar', initials(message.from));
      const content = node('div', 'message-content');
      const meta = node('div', 'message-meta');
      meta.append(node('strong', null, own ? 'Bạn' : message.from));
      meta.append(node('time', null, clock(message.ts)));
      const bubble = node('div', 'message-bubble', message.text);
      content.append(meta, bubble);
      if (message.status)
        content.append(
          node(
            'div',
            'message-status ' + (message.status === 'failed' ? 'failed' : ''),
            message.status === 'queued'
              ? 'Đang gửi tới server…'
              : message.status === 'accepted'
                ? 'Server đã xếp hàng gửi'
                : message.status === 'failed'
                  ? 'Gửi không thành công'
                  : 'Đã đến server',
          ),
        );
      row.append(avatar, content);
      holder.append(row);
    }
    if (nearBottom || current.length < 5)
      holder.scrollTop = holder.scrollHeight;
  }
  function receipt(requestId, status, serverId = null) {
    if (!Number.isInteger(requestId)) return;
    const message = pending.get(requestId);
    if (!message) {
      earlyReceipts.set(requestId, { status, serverId });
      return;
    }
    message.status = status;
    if (serverId) message.serverId = serverId;
    pending.delete(requestId);
    if (status === 'failed')
      notice(
        'Server từ chối tin nhắn. Kiểm tra người nhận hoặc kết nối.',
        true,
      );
    renderMessages();
  }
  function handleChatEvent(event) {
    const body = event.body || {};
    if (typeof body.text !== 'string' || typeof body.from !== 'string') return;
    if (body.scope !== 'direct' && body.scope !== 'broadcast') return;
    const id = body.server_msg_id;
    if (Number.isInteger(id) && seenServerMessages.has(id)) return;
    if (Number.isInteger(id)) seenServerMessages.add(id);
    const key =
      body.scope === 'broadcast'
        ? 'global'
        : keyFor(body.from === me ? body.to : body.from);
    remember(key, {
      from: body.from,
      text: body.text,
      ts: body.ts || event.ts || Date.now(),
      serverId: id,
      status: null,
    });
  }
  function updateFileRecipients() {
    const select = $('fileRecipient');
    const selected = select.value;
    select.replaceChildren(new Option('Chọn người nhận', ''));
    for (const user of onlineUsers.filter((u) => u !== me))
      select.add(new Option(user, user));
    if (onlineUsers.includes(selected) && selected !== me)
      select.value = selected;
    $('fileSendButton').disabled =
      state !== 'online' || !bridgeReachable || offeringFile;
  }
  function formatSize(count) {
    return `${Number(count || 0).toLocaleString('vi-VN')} bytes`;
  }
  function handleFileEvent(event) {
    const body = event.body || {};
    const tid = body.transfer_id;
    if (event.type === 'FILE_QUEUED' && Number.isInteger(body.request_id)) {
      const item = {
        transfer_id: `pending:${body.request_id}`,
        role: 'sender',
        peer: body.to,
        filename: body.filename,
        size: body.size,
        status: 'queued',
        bytes_received: 0,
      };
      files.set(item.transfer_id, item);
      fileRequests.set(body.request_id, item.transfer_id);
    } else if (event.type === 'FILE_OFFER_REJECTED') {
      const id = fileRequests.get(body.request_id);
      if (id && files.has(id)) files.get(id).status = 'FAILED';
      batch = [];
      offeringFile = false;
      updateFileRecipients();
    } else if (event.type === 'FILE_OFFER_ACK' && typeof tid === 'string') {
      const old = fileRequests.get(event.reply_to);
      const item = (old && files.get(old)) || { role: 'sender' };
      if (old) files.delete(old);
      files.set(tid, {
        ...item,
        transfer_id: tid,
        status: 'offered',
        filename: body.filename || item.filename || 'file',
        size: body.size || item.size || 0,
        peer: body.to || item.peer || '?',
      });
    } else if (event.type === 'FILE_OFFER' && typeof tid === 'string') {
      files.set(tid, {
        transfer_id: tid,
        role: 'receiver',
        peer: body.from,
        filename: body.filename,
        size: body.size,
        status: 'offered',
        bytes_received: 0,
      });
      $('fileDrawer').open = true;
      notice(`Có yêu cầu nhận file từ ${String(body.from || 'người dùng')}.`);
    } else if (typeof tid === 'string' && files.has(tid)) {
      const item = files.get(tid);
      if (event.type === 'FILE_START') item.status = 'transferring';
      if (
        event.type === 'FILE_PROGRESS' &&
        item.role === 'receiver' &&
        Number.isInteger(body.received_bytes)
      )
        item.bytes_received = Math.min(
          item.size,
          Math.max(item.bytes_received || 0, body.received_bytes),
        );
      if (
        event.type === 'FILE_PROGRESS' &&
        item.role === 'sender' &&
        Number.isInteger(body.confirmed_bytes)
      )
        item.confirmed_bytes = Math.min(
          item.size,
          Math.max(item.confirmed_bytes || 0, body.confirmed_bytes),
        );
      if (event.type === 'FILE_RESULT') {
        if (item.role === 'sender' && offeringFile) sendNextFile();
        item.status = body.status || 'FAILED';
        if (item.status === 'COMPLETED')
          notice(`Đã truyền xong ${item.filename}.`);
        else notice(`Truyền file ${item.filename}: ${item.status}.`, true);
      }
    }
    renderFiles();
  }
  function renderFiles() {
    const box = $('fileActivity');
    box.replaceChildren();
    const recent = [...files.values()].slice(-10).reverse();
    if (!recent.length) {
      box.append(node('p', 'file-empty', 'Chưa có file nào trong phiên này.'));
      return;
    }
    const statuses = {
      queued: 'Đã xếp hàng gửi yêu cầu',
      offered: 'Chờ phản hồi',
      accepting: 'Đang chấp nhận',
      rejecting: 'Đang từ chối',
      responding: 'Đang xử lý',
      transferring: 'Đang truyền qua reliable UDP',
      COMPLETED: 'Hoàn tất và kiểm tra hash',
      REJECTED: 'Người nhận từ chối',
      FAILED: 'Truyền thất bại',
    };
    for (const item of recent) {
      const card = node('article', 'file-card');
      const top = node('div', 'file-card-top');
      top.append(
        node('strong', null, item.filename || 'Tệp tin'),
        node(
          'small',
          null,
          item.role === 'receiver'
            ? `Từ ${item.peer || '?'}`
            : `Đến ${item.peer || '?'}`,
        ),
      );
      card.append(
        top,
        node(
          'small',
          null,
          `${formatSize(item.size)} • ${statuses[item.status] || item.status}`,
        ),
      );
      const done = item.status === 'COMPLETED';
      if (item.role === 'receiver' || item.role === 'sender') {
        const raw =
          item.role === 'receiver' ? item.bytes_received : item.confirmed_bytes;
        const value = done
          ? item.size
          : Math.min(item.size, Math.max(0, raw || 0));
        const pct =
          item.size > 0
            ? Math.min(100, Math.floor((value * 100) / item.size))
            : 0;
        const progress = document.createElement('progress');
        progress.max = Math.max(1, item.size);
        progress.value = value;
        progress.setAttribute(
          'aria-label',
          item.role === 'sender'
            ? 'Tiến độ bên nhận xác nhận'
            : 'Tiến độ nhận file',
        );
        const label =
          item.role === 'sender' ? 'người nhận đã xác nhận' : 'đã nhận';
        card.append(
          progress,
          node(
            'small',
            null,
            `${pct}% · ${formatSize(value)} / ${formatSize(item.size)} ${label}`,
          ),
        );
        if (
          item.role === 'sender' &&
          !done &&
          value === 0 &&
          item.status === 'transferring'
        )
          card.append(
            node(
              'small',
              null,
              'Đang chờ xác nhận block đầu tiên từ người nhận…',
            ),
          );
      }
      const actions = node('div', 'file-card-actions');
      if (item.role === 'receiver' && item.status === 'offered') {
        for (const [label, action, style] of [
          ['Chấp nhận', 'accept', 'file-action'],
          ['Từ chối', 'reject', 'file-action file-secondary'],
        ]) {
          const btn = node('button', style, label);
          btn.type = 'button';
          btn.addEventListener('click', () =>
            answerFile(item.transfer_id, action),
          );
          actions.append(btn);
        }
      }
      if (item.role === 'receiver' && done) {
        const btn = node('button', 'file-action', 'Tải xuống máy');
        btn.type = 'button';
        btn.addEventListener('click', () =>
          downloadFile(item.transfer_id, item.filename),
        );
        actions.append(btn);
      }
      if (actions.childElementCount) card.append(actions);
      box.append(card);
    }
  }
  async function answerFile(tid, action) {
    const item = files.get(tid);
    if (
      state !== 'online' ||
      !bridgeReachable ||
      !item ||
      item.status !== 'offered'
    )
      return;
    item.status = 'responding';
    renderFiles();
    try {
      await request(`/api/file/${action}`, {
        method: 'POST',
        payload: { transfer_id: tid },
      });
      item.status = action === 'accept' ? 'accepting' : 'rejecting';
    } catch (err) {
      item.status = 'offered';
      notice(`Không xử lý được file: ${err.message}`, true);
    }
    renderFiles();
  }
  async function downloadFile(tid, filename) {
    if (state !== 'online' || !bridgeReachable) return;
    try {
      const response = await fetch(
        `/api/file/download/${encodeURIComponent(tid)}`,
        { headers: { 'X-Bridge-Token': token }, cache: 'no-store' },
      );
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 3000);
    } catch (err) {
      notice(`Không tải xuống được: ${err.message}`, true);
    }
  }
  $('fileOfferForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (offeringFile || state !== 'online' || !bridgeReachable) return;
    const recipient = $('fileRecipient').value;
    const selected = Array.from($('fileInput').files);
    if (
      !selected.length ||
      selected.some((f) => f.size < 1 || f.size > MAX_FILE)
    ) {
      notice('Mỗi file phải từ 1 byte đến 50 MiB.', true);
      return;
    }
    batch = selected.map((file) => ({ file, recipient }));
    offeringFile = true;
    sendNextFile();
  });
  async function sendNextFile() {
    if (!batch.length || state !== 'online' || !bridgeReachable) {
      offeringFile = false;
      updateFileRecipients();
      return;
    }
    const { file, recipient } = batch.shift();
    if (!recipient) {
      batch = [];
      offeringFile = false;
      updateFileRecipients();
      return;
    }
    if (!Number.isInteger(file.size) || file.size < 1 || file.size > MAX_FILE) {
      notice('Mỗi file tối đa 50 MiB.', true);
      return;
    }
    offeringFile = true;
    updateFileRecipients();
    try {
      const response = await fetch('/api/file/offer', {
        method: 'POST',
        cache: 'no-store',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Bridge-Token': token,
          'X-Recipient': recipient,
          'X-File-Name': encodeURIComponent(file.name),
        },
        body: file,
      });
      const data = await response.json();
      if (!response.ok)
        throw new Error(data.error || `HTTP ${response.status}`);
      $('fileInput').value = '';
      notice('Đã gửi yêu cầu file. Đang chờ người nhận chấp nhận.');
    } catch (err) {
      batch = [];
      offeringFile = false;
      updateFileRecipients();
      notice(`Không gửi được file: ${err.message}`, true);
    }
  }
  function processEvents(events) {
    for (const event of events) {
      if (event.type.startsWith('FILE_')) handleFileEvent(event);
      if (event.type === 'CHAT_EVENT') handleChatEvent(event);
      if (event.type === 'CHAT_ACCEPTED')
        receipt(event.reply_to, 'accepted', event.body?.server_msg_id);
      if (event.type === 'ERROR') {
        receipt(event.reply_to, 'failed');
        if (event.body?.message) notice(String(event.body.message), true);
      }
      if (event.type === 'BRIDGE_ERROR')
        notice('Phiên UDP đã ngắt. Vui lòng đăng nhập lại.', true);
    }
  }
  function renderStatus(status) {
    const next = status.state || 'disconnected';
    const nextUser = status.username || null;
    if (me && (next !== 'online' || nextUser !== me)) {
      resetChat();
      $('password').value = '';
    }
    state = next;
    me = next === 'online' ? nextUser : null;
    const isOnline = state === 'online';
    $('connectionBadge').className =
      'conn-pill' +
      (isOnline && bridgeReachable
        ? ' online'
        : state === 'error' || !bridgeReachable
          ? ' error'
          : '');
    $('connectionText').textContent = !bridgeReachable
      ? 'Bridge không phản hồi'
      : {
          online: 'Đã kết nối',
          connecting: 'Đang kết nối',
          disconnecting: 'Đang ngắt kết nối',
          disconnected: 'Chưa kết nối',
          error: 'Mất kết nối',
        }[state] || state;
    $('loginView').hidden = isOnline;
    $('workspaceView').hidden = !isOnline;
    $('targetServer').textContent =
      `${status.server_host || '127.0.0.1'}:${status.tcp_port || 9000}`;
    if (isOnline) {
      $('myUsername').textContent = me;
      $('myAvatar').textContent = initials(me);
      $('sessionState').textContent = 'Online';
      $('currentServer').textContent = status.server_host || '127.0.0.1';
      onlineUsers = Array.isArray(status.users) ? status.users : [];
      if (Array.isArray(status.transfers)) {
        for (const item of status.transfers)
          if (item.transfer_id) files.set(item.transfer_id, { ...item });
      }
      renderContacts();
      renderFiles();
    }
    if (state === 'error' || state === 'disconnecting') {
      setResilienceBanner(
        'session',
        status.error || 'Kết nối UDP đã ngắt. Hãy đăng nhập lại.',
      );
    } else if (bridgeReachable) {
      setResilienceBanner(null);
    }
    refreshAvailability();
    if (status.error && !isOnline && !busy) loginError(status.error);
    else if (isOnline) loginError('');
  }
  async function poll() {
    if (polling || busy) return;
    polling = true;
    try {
      const result = await request(
        `/api/events?since=${encodeURIComponent(cursor)}`,
      );
      bridgeReachable = true;
      if (result.gap)
        notice(
          'Một phần sự kiện cũ không còn trong bộ đệm. Lịch sử chat có thể thiếu.',
          true,
        );
      processEvents(result.events || []);
      cursor = result.cursor;
      renderStatus(result);
    } catch (err) {
      bridgeReachable = false;
      $('connectionBadge').className = 'conn-pill error';
      $('connectionText').textContent = 'Bridge không phản hồi';
      setResilienceBanner('bridge');
      refreshAvailability();
    } finally {
      polling = false;
    }
  }
  function updateBytes() {
    const count = encoder.encode($('messageInput').value).length;
    $('byteCounter').textContent = `${count} / ${MAX_BYTES} bytes`;
    $('byteCounter').classList.toggle('limit-exceeded', count > MAX_BYTES);
    $('sendButton').disabled =
      state !== 'online' ||
      !bridgeReachable ||
      sending ||
      count === 0 ||
      count > MAX_BYTES ||
      (activeChat !== 'global' && !onlineUsers.includes(activeChat.slice(3)));
  }
  $('retryBridgeButton').addEventListener('click', () => poll());
  $('contactSearch').addEventListener('input', renderContacts);
  $('globalChatButton').addEventListener('click', () => selectChat('global'));
  $('messageInput').addEventListener('input', updateBytes);
  $('messageInput').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      $('chatForm').requestSubmit();
    }
  });
  $('chatForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (state !== 'online' || !bridgeReachable || sending) return;
    const value = $('messageInput').value;
    if (!value.trim() || encoder.encode(value).length > MAX_BYTES) {
      notice(
        'Tin nhắn phải có nội dung và không vượt quá 1000 byte UTF-8.',
        true,
      );
      return;
    }
    const key = activeChat;
    const global = key === 'global';
    const target = global ? null : key.slice(3);
    if (!global && !onlineUsers.includes(target)) {
      notice('Người nhận không online.', true);
      return;
    }
    sending = true;
    updateBytes();
    notice('');
    try {
      const path = global ? '/api/chat/broadcast' : '/api/chat/direct';
      const payload = global ? { text: value } : { to: target, text: value };
      const result = await request(path, { method: 'POST', payload });
      $('messageInput').value = '';
      if (global) {
        notice(
          'Đã xếp hàng gửi. Tin nhắn sẽ xuất hiện khi server phát lại vào Global Chat.',
        );
      } else {
        const message = {
          from: me,
          text: value,
          ts: Date.now(),
          status: 'queued',
          requestId: result.request_id,
        };
        remember(key, message);
        pending.set(result.request_id, message);
        if (earlyReceipts.has(result.request_id)) {
          const response = earlyReceipts.get(result.request_id);
          earlyReceipts.delete(result.request_id);
          receipt(result.request_id, response.status, response.serverId);
        }
      }
    } catch (err) {
      notice(`Không gửi được: ${err.message}. Nội dung vẫn ở ô soạn.`, true);
    } finally {
      sending = false;
      updateBytes();
      $('messageInput').focus();
    }
  });
  $('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;
    const username = $('username').value.trim();
    const password = $('password').value;
    if (!username || !password) {
      loginError('Vui lòng nhập tên đăng nhập và mật khẩu.');
      return;
    }
    busy = true;
    loginError('');
    $('loginButton').disabled = true;
    $('loginButton').firstElementChild.textContent =
      'Đang kết nối & xác thực...';
    try {
      const result = await request('/api/login', {
        method: 'POST',
        payload: { username, password },
      });
      $('password').value = '';
      resetChat();
      renderStatus(result);
    } catch (err) {
      $('password').value = '';
      loginError(err.message || 'Không thể đăng nhập.');
    } finally {
      busy = false;
      $('loginButton').disabled = false;
      $('loginButton').firstElementChild.textContent =
        'Đăng nhập vào workspace';
      await poll();
    }
  });
  $('logoutButton').addEventListener('click', async () => {
    if (
      busy ||
      !confirm(
        'Ngắt phiên trên máy này? Server sẽ cập nhật offline sau timeout nếu chưa có LOGOUT.',
      )
    )
      return;
    busy = true;
    try {
      const result = await request('/api/logout', {
        method: 'POST',
        payload: {},
      });
      resetChat();
      renderStatus(result);
      loginError('');
    } catch (err) {
      notice(`Không ngắt được phiên: ${err.message}`, true);
    } finally {
      busy = false;
      await poll();
    }
  });
  $('revealPassword').addEventListener('click', () => {
    const field = $('password');
    const reveal = field.type === 'password';
    field.type = reveal ? 'text' : 'password';
    $('revealPassword').textContent = reveal ? 'Ẩn' : 'Hiện';
  });
  (async () => {
    try {
      const data = await request('/api/status');
      token = data.bridge_token;
      bridgeReachable = true;
      renderStatus(data);
      await poll();
    } catch (err) {
      bridgeReachable = false;
      setResilienceBanner('bridge');
      loginError('Không kết nối được HTTP Bridge trên localhost.');
      refreshAvailability();
    }
    setInterval(poll, 900);
  })();
})();
