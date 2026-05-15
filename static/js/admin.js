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

function deleteUser(username) {
    if (confirm('确定要删除用户 ' + username + ' 吗？此操作不可恢复。')) {
        fetch('/admin/users/' + username, {
            method: 'DELETE'
        }).then(function(response) {
            if (response.ok) {
                window.location.reload();
            } else {
                response.json().then(function(data) {
                    alert(data.error || '删除失败');
                });
            }
        });
    }
}

function resetTotp(username) {
    if (confirm('确定要重置 ' + username + ' 的 TOTP 密钥吗？用户需要重新配置验证器。')) {
        fetch('/admin/users/' + username + '/totp', {
            method: 'POST'
        }).then(function(response) { return response.json(); })
        .then(function(data) {
            document.getElementById('qrCodeContainer').innerHTML =
                '<img src="' + data.qr_code + '" alt="QR Code">';
            document.getElementById('secretKey').textContent = data.secret;
            document.getElementById('totpModal').classList.add('active');
        });
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

document.getElementById('editNameForm').addEventListener('submit', function(e) {
	e.preventDefault();
	var username = document.getElementById('editUsername').value;
	var name = document.getElementById('editName').value;
	
	fetch('/admin/users/' + username + '/name', {
		method: 'PUT',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ name: name })
	}).then(response => {
		if (response.ok) {
			window.location.reload();
		} else {
			response.json().then(data => {
				alert(data.error || '修改失败');
			});
		}
	});
});
        
document.querySelectorAll('.modal').forEach(function(modal) {
    modal.addEventListener('click', function(e) {
        if (e.target === this && this.id === 'userModal') {
            closeModal();
        }
    });
});
