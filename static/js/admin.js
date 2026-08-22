function openModal() {
    document.getElementById('userModal').classList.add('active');
}

function closeModal() {
    document.getElementById('userModal').classList.remove('active');
    document.getElementById('userForm').reset();
    document.getElementById('passwordField').style.display = 'none';
    document.getElementById('is_sub_admin').value = '0';
    document.getElementById('tabUser').classList.add('active');
    document.getElementById('tabSubAdmin').classList.remove('active');
    document.getElementById('password').required = false;
}

function switchTab(type) {
    var tabUser = document.getElementById('tabUser');
    var tabSubAdmin = document.getElementById('tabSubAdmin');
    var isSubAdmin = document.getElementById('is_sub_admin');
    var passwordField = document.getElementById('passwordField');
    var passwordInput = document.getElementById('password');

    if (type === 'user') {
        tabUser.classList.add('active');
        tabSubAdmin.classList.remove('active');
        isSubAdmin.value = '0';
        passwordField.style.display = 'none';
        passwordInput.required = false;
    } else {
        tabUser.classList.remove('active');
        tabSubAdmin.classList.add('active');
        isSubAdmin.value = '1';
        passwordField.style.display = 'block';
        passwordInput.required = true;
    }
}

function closeTotpModal() {
    document.getElementById('totpModal').classList.remove('active');
    window.location.reload();
}

function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
}

function deleteUser(username) {
    if (confirm('确定要删除用户 ' + username + ' 吗？此操作不可恢复。')) {
        fetch('/admin/users/' + username, {
            method: 'DELETE',
            headers: { 'X-CSRF-Token': getCsrfToken() }
        }).then(function(response) {
            if (response.ok) {
                window.location.reload();
            } else {
                response.json().then(function(data) {
                    alert(data.error || data.message || '删除失败');
                }).catch(function() { alert('删除失败'); });
            }
        }).catch(function() { alert('网络错误，请稍后重试'); });
    }
}

function resetTotp(username) {
    if (confirm('确定要重置 ' + username + ' 的 TOTP 密钥吗？用户需要重新配置验证器。')) {
        fetch('/admin/users/' + username + '/totp', {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() }
        }).then(function(response) {
            if (!response.ok) {
                return response.json().then(function(data) {
                    alert(data.error || data.message || '重置失败');
                }).catch(function() { alert('重置失败'); });
            }
            return response.json().then(function(data) {
                document.getElementById('qrCodeContainer').innerHTML =
                    '<img src="' + data.qr_code + '" alt="QR Code">';
                document.getElementById('secretKey').textContent = data.secret;
                document.getElementById('totpModal').classList.add('active');
            });
        }).catch(function() { alert('网络错误，请稍后重试'); });
    }
}
function editName(username, currentName) {
	document.getElementById('editUsername').value = username;
	document.getElementById('editName').value = currentName;
	document.getElementById('editNameModal').classList.add('active');
}

function closeEditNameModal() {
	document.getElementById('editNameModal').classList.remove('active');
	document.getElementById('editNameForm').reset();
}

function openPasswordModal(username, isSelf) {
    document.getElementById('passwordUsername').value = username;
    document.getElementById('isSelfPasswordChange').value = isSelf ? '1' : '0';
    document.getElementById('passwordModalTitle').textContent = isSelf ? '修改我的密码' : '修改 ' + username + ' 的密码';
    document.getElementById('currentPasswordGroup').style.display = isSelf ? 'block' : 'none';
    document.getElementById('currentPassword').required = isSelf;
    document.getElementById('passwordModal').classList.add('active');
}

function closePasswordModal() {
    document.getElementById('passwordModal').classList.remove('active');
    document.getElementById('passwordForm').reset();
}

document.getElementById('editNameForm').addEventListener('submit', function(e) {
	e.preventDefault();
	var username = document.getElementById('editUsername').value;
	var name = document.getElementById('editName').value;
	
	fetch('/admin/users/' + username + '/name', {
		method: 'PUT',
		headers: {
			'Content-Type': 'application/json',
			'X-CSRF-Token': getCsrfToken()
		},
		body: JSON.stringify({ name: name })
	}).then(response => {
		if (response.ok) {
			window.location.reload();
		} else {
			response.json().then(data => {
				alert(data.error || data.message || '修改失败');
			}).catch(() => alert('修改失败'));
		}
	}).catch(() => alert('网络错误，请稍后重试'));
});

document.getElementById('passwordForm').addEventListener('submit', function(e) {
    e.preventDefault();
    var username = document.getElementById('passwordUsername').value;
    var isSelf = document.getElementById('isSelfPasswordChange').value === '1';
    var payload = {
        new_password: document.getElementById('newPassword').value
    };

    if (isSelf) {
        payload.current_password = document.getElementById('currentPassword').value;
    }

    fetch('/admin/users/' + username + '/password', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCsrfToken()
        },
        body: JSON.stringify(payload)
    }).then(function(response) {
        if (response.ok) {
            alert('密码修改成功');
            closePasswordModal();
        } else {
            response.json().then(function(data) {
                alert(data.message || data.error || '修改失败');
            }).catch(function() { alert('修改失败'); });
        }
    }).catch(function() { alert('网络错误，请稍后重试'); });
});
         
document.querySelectorAll('.modal').forEach(function(modal) {
    modal.addEventListener('click', function(e) {
        if (e.target === this && this.id === 'userModal') {
            closeModal();
        } else if (e.target === this && this.id === 'editNameModal') {
            closeEditNameModal();
        } else if (e.target === this && this.id === 'passwordModal') {
            closePasswordModal();
        }
    });
});
