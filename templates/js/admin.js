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
        }).then(response => {
            if (response.ok) {
                window.location.reload();
            } else {
                response.json().then(data => {
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
        }).then(response => response.json())
        .then(data => {
            document.getElementById('qrCodeContainer').innerHTML =
                '<img src="' + data.qr_code + '" alt="QR Code">';
            document.getElementById('secretKey').textContent = data.secret;
            document.getElementById('totpModal').classList.add('active');
        });
    }
}

document.querySelectorAll('.modal').forEach(function(modal) {
    modal.addEventListener('click', function(e) {
        if (e.target === this && this.id === 'userModal') {
            closeModal();
        }
    });
});
