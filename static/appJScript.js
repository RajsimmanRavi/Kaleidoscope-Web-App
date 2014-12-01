
$('#logOut').click(function(){
   console.log('here');
   $.ajax({
            type: 'GET',
            url: "/auth/logout",
            success: function (data) {
                alert("success")
            }
        });
});

function authenticateUser(form){
    if (form.uName.value == "raj" && form.pass.value == "ravi")        
      window.location.replace("static/homePage.html");
    else
      alert("incorrect");      
}

