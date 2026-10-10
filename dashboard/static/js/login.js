document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    const errorMessage = document.getElementById('errorMessage');
    
    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        errorMessage.classList.remove('show');
        errorMessage.textContent = '';
        
        try {
            const formData = new FormData();
            formData.append('username', username);
            formData.append('password', password);
            
            const response = await fetch('/login', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (data.success) {
                window.location.href = data.redirect || '/';
            } else {
                errorMessage.textContent = data.error || 'Unable to sign in';
                errorMessage.classList.add('show');
            }
        } catch (error) {
            errorMessage.textContent = 'Unable to reach the authentication service';
            errorMessage.classList.add('show');
        }
    });
});
