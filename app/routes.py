import re

from flask import Blueprint, jsonify, render_template, request

from . import models as M

bp = Blueprint('lab', __name__)


def _clean():
    M.reset_users()


def _public(u):
    return {k: v for k, v in u.items() if k not in ('password', 'flag')}


def _sensitive(u):
    return {k: v for k, v in u.items() if k != 'flag'}


# ---------- endpoint API (RENTAN / FIXED) ----------

def api_profile(uid):
    u = M.find_user(uid)
    if not u:
        return {'ok': False, 'error': 'profile tidak ada'}
    if M.setting('s1'):
        return {'ok': True, 'role': u['role'], 'mode': 'RENTAN',
                'profile': _sensitive(u)}
    if uid != M.SESSION_USER:
        return {'ok': False, 'error': '403: hanya boleh akses profil sendiri',
                'mode': 'FIXED'}
    return {'ok': True, 'role': u['role'], 'mode': 'FIXED', 'profile': _public(u)}


def api_admin_users():
    if M.setting('s2'):
        return {'ok': True, 'mode': 'RENTAN', 'users': [_sensitive(u) for u in M.USERS]}
    me = M.find_user(M.SESSION_USER)
    if me['role'] != 'admin':
        return {'ok': False, 'error': '403: butuh role admin', 'mode': 'FIXED'}
    return {'ok': True, 'mode': 'FIXED', 'users': [_public(u) for u in M.USERS]}


def api_export(ids):
    if M.setting('s3'):
        rows = []
        for i in ids:
            u = M.find_user(i)
            if u:
                rows.append(_sensitive(u))
        return {'ok': True, 'mode': 'RENTAN', 'exported': rows, 'count': len(rows)}
    if any(i != M.SESSION_USER for i in ids):
        return {'ok': False, 'error': '403: export hanya untuk data sendiri', 'mode': 'FIXED'}
    rows = [_public(M.find_user(i)) for i in ids if M.find_user(i)]
    return {'ok': True, 'mode': 'FIXED', 'exported': rows, 'count': len(rows)}


def api_update_profile(uid, new_email):
    u = M.find_user(uid)
    if not u:
        return {'ok': False, 'error': 'profile tidak ada'}
    if M.setting('s4'):
        u['email'] = new_email
        return {'ok': True, 'mode': 'RENTAN', 'updated': uid, 'email': u['email'],
                'note': 'email korban disalin ke attacker -> siap reset password'}
    if uid != M.SESSION_USER:
        return {'ok': False, 'error': '403: hanya bisa update profil sendiri', 'mode': 'FIXED'}
    u['email'] = new_email
    return {'ok': True, 'mode': 'FIXED', 'updated': uid, 'email': u['email']}


# ---------- PoC ----------

def _finish(ok, steps, flag=None):
    out = {'steps': steps, 'ok': ok}
    if flag:
        out['flag'] = flag
    return out


def _find_flag(payload):
    m = re.search(r'[A-Z0-9]+-LAB\{[^}]+\}', payload)
    return m.group(0) if m else None


def _poc_s1():
    _clean()
    steps = ['1. Attacker (id=3) penasaran dgn endpoint profil:',
             '   GET /api/v1/profile/2  (id korban)']
    r = api_profile(2)
    if not M.setting('s1'):
        steps += ['FIXED: endpoint wajib `uid == session.user_id`',
                  '   -> 403 "hanya boleh akses profil sendiri" -> BLOCKED.']
        return _finish(False, steps)
    steps += [f'2. (RENTAN) Tidak ada check ownership -> profil victim {r["role"]} keluar:',
              f'   {r["profile"]}']
    steps += ['3. PII victim (email, phone, password) bocor -> horizontal IDOR.']
    flag = _find_flag(str(r['profile']))
    M.log('s1', 'horizontal IDOR: baca profil user lain (id=2)')
    return _finish(True, steps, flag or M.FLAG)


def _poc_s2():
    _clean()
    steps = ['1. Endpoint admin coba dipanggil account biasa (attacker):',
             '   GET /api/v1/admin/users']
    r = api_admin_users()
    if not M.setting('s2'):
        steps += ['FIXED: butuh role admin -> attacker (role user)',
                  '   -> 403 "butuh role admin" -> BLOCKED.']
        return _finish(False, steps)
    long = str([_sensitive(u) for u in M.USERS])
    steps += [f'2. (RENTAN) Tidak ada check peran -> daftar SEMUA user: {r["users"]}',
              '3. Termasuk secret/password & flag admin -> vertical privilege escalation.']
    M.log('s2', 'vertical IDOR: endpoint admin tanpa cek role')
    return _finish(True, steps, M.FLAG)


def _poc_s3():
    _clean()
    steps = ['1. Fitur export pakai array id dari body (tanpa baten user milik siapa):',
             '   POST /api/v1/export {"user_ids": [1,2,3]}']
    r = api_export([1, 2, 3])
    if not M.setting('s3'):
        steps += ['FIXED: export di-bind ke session (user_id sendiri) + limit',
                  '   -> hanya data sendiri -> BLOCKED.']
        return _finish(False, steps)
    steps += ['2. (RENTAN) Mass-assignment id: seluruh dokumen user ter-export:',
              f'   {r["exported"]}',
              '3. Attacker tarik semua data (drain) lewat satu request.']
    flag = _find_flag(str(r['exported']))
    M.log('s3', 'mass IDOR export: array user_ids sembarang')
    return _finish(True, steps, flag or M.FLAG)


def _poc_s4():
    _clean()
    steps = ['1. Attacker ganti EMAIL profil dengan nembak user_id korban:',
             '   POST /api/v1/profile/update {"user_id": 2, "email": "attacker@evil.com"}']
    r = api_update_profile(2, 'attacker@evil.com')
    if not M.setting('s4'):
        steps += ['FIXED: user_id dipaksa session (attacker), bukan dari body',
                  '   -> email attacker yg berubah -> BLOCKED.']
        return _finish(False, steps)
    steps += [f'2. (RENTAN) Update email JADI milik victim (id=2): {r["email"]}',
              '3. Attacker klik "lupa password" utk email miliknya → reset victim.',
              '4. Login sebagai victim@bank.test → ATO.']
    flag = M.FLAG if r.get('updated') == 2 and r['email'] == 'attacker@evil.com' else None
    if flag:
        M.log('s4', 'IDOR->ATO: ubah email victim lewat user_id di body')
    return _finish(bool(flag), steps, flag)


POCS = {'s1': _poc_s1, 's2': _poc_s2, 's3': _poc_s3, 's4': _poc_s4}


# ---------- halaman ----------

@bp.route('/')
def index():
    return render_template('index.html', modes=M.all_settings())


@bp.route('/logs')
def logs():
    return render_template('logs.html', logs=M.last_logs())


@bp.route('/run/<sid>')
def run_page(sid):
    if sid not in POCS:
        return 'unknown', 404
    return render_template('result.html', sid=sid, d=POCS[sid](),
                           label={'s1': 'Horizontal IDOR — baca profil user lain',
                                  's2': 'Vertical IDOR — endpoint admin tanpa cek role',
                                  's3': 'Mass/export IDOR — arrya user_ids sembarang',
                                  's4': 'IDOR → ATO — ganti email korban via user_id di body'}[sid])


@bp.route('/api/state')
def api_state():
    return jsonify(M.all_settings())


@bp.route('/api/toggle/<sid>', methods=['POST'])
def api_toggle(sid):
    if sid not in ('s1', 's2', 's3', 's4'):
        return jsonify({'error': 'invalid id'}), 400
    data = request.get_json(silent=True) or {}
    if 'vulnerable' in data or 'on' in data:
        v = bool(data.get('vulnerable', data.get('on', True)))
    else:
        v = not M.setting(sid)
    M.set_setting(sid, v)
    M.log('setting', f'{sid} -> {"RENTAN" if M.setting(sid) else "FIXED"}')
    return jsonify({'id': sid, 'vulnerable': M.setting(sid)})


@bp.route('/api/poc/<sid>', methods=['POST'])
def api_poc(sid):
    if sid not in POCS:
        return jsonify({'error': 'invalid id'}), 400
    return jsonify({'id': sid, **POCS[sid]()})


# ---------- endpoint manual (curl-friendly) ----------

@bp.route('/api/v1/profile/<int:uid>', methods=['GET'])
def manual_profile(uid):
    return jsonify(api_profile(uid))


@bp.route('/api/v1/admin/users', methods=['GET'])
def manual_admin():
    return jsonify(api_admin_users())


@bp.route('/api/v1/export', methods=['POST'])
def manual_export():
    body = request.get_json(silent=True) or {}
    ids = body.get('user_ids', [])
    return jsonify(api_export([int(i) for i in ids]))


@bp.route('/api/v1/profile/update', methods=['POST'])
def manual_update():
    body = request.get_json(silent=True) or {}
    uid = int(body.get('user_id', M.SESSION_USER))
    email = body.get('email', '')
    return jsonify(api_update_profile(uid, email))