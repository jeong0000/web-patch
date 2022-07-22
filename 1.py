<?php
session_start();
include "./config.php";

if($_GET['page'] == "login"){
    session_start();
    try{
        $input = json_decode(file_get_contents('php://input'), true);
    }
    catch(Exception $e){
        exit("<script>alert(`wrong input`);history.go(-1);</script>");
    }
    $db = dbconnect();
    
    $input['id'] = mysqli_real_escape_string($db, $input['id']);
    $input['email'] = mysqli_real_escape_string($db, $input['email']);
    $input['pw'] = mysqli_real_escape_string($db, $input['pw']);
    
    /*
    $input['id'] = htmlspecialchars($input['id']);
    $input['email'] = htmlspecialchars($db, $input['email']);
    $input['pw'] = htmlspecialchars($db, $input['pw']);*/
    
    /*
    if( $input['id'] != 'admin'){
        $input['pw'] = hash('sha256', $input['pw'], true); 
    }*/

    
    
    $query = "select id,pw from member where id='{$input['id']}'";
    $result = mysqli_fetch_array(mysqli_query($db,$query));
    if($result['id'] && $result['pw'] == $input['pw']){
        $_SESSION['id'] = $result['id'];
        $_SESSION['pw'] = $result['pw'];
        $_SESSION['email'] = $result['email'];
        exit("<script>alert(`login ok`);location.href=`/`;</script>");
    }
    else{ exit("<script>alert(`login fail`);history.go(-1);</script>"); }
}
if($_GET['page'] == "join"){
    session_start();
    try{
        $input = json_decode(file_get_contents('php://input'), true);
    }
    catch(Exception $e){
        exit("<script>alert(`wrong input`);history.go(-1);</script>");
    }
    $db = dbconnect();
    if(strlen($input['id']) > 256) exit("<script>alert(`userid too long`);history.go(-1);</script>");
    if(strlen($input['email']) > 120) exit("<script>alert(`email too long`);history.go(-1);</script>");
    if(!filter_var($input['email'],FILTER_VALIDATE_EMAIL)) exit("<script>alert(`wrong email`);history.go(-1);</script>");
    
    $input['id'] = mysqli_real_escape_string($db, $input['id']);
    $input['email'] = mysqli_real_escape_string($db, $input['email']);
    $input['pw'] = mysqli_real_escape_string($db, $input['pw']);
    
    /*
    $input['id'] = str_replace('\\', '', input['id']);
    $input['id'] = str_replace('/', '', input['id']);
    $input['id'] = str_replace('\\\\', '', input['id']);
    $input['email'] = str_replace('\\', '', $input['email']);
    $input['email'] = str_replace('/', '', $input['email']);
    $input['email'] = str_replace('\\\\', '', $input['email']);
    $input['pw'] = str_replace('\\', '', $input['pw']);
    $input['pw'] = str_replace('/', '', $input['pw']);
    $input['pw'] = str_replace('\\\\', '', $input['pw']);
    */
    
    /*
    $input['id'] = htmlspecialchars($input['id']);
    $input['email'] = htmlspecialchars($db, $input['email']);
    $input['pw'] = htmlspecialchars($db, $input['pw']);*/
    
    /*
    $num = preg_match('/[0-9]/u', $input['pw']);
    $eng = preg_match('/[a-z]/u', $input['pw']);
    $spe = preg_match("/[\!\@\#\$\%\^\&\*]/u",$input['pw']);
    
    if(strlen($input['pw']) < 6){
        exit("<script>history.go(-1);</script>");
    }
    else if(preg_match("/\s/u", $input['pw']) == true)
    {
        exit("<script>history.go(-1);</script>"); // trim
    }
    else if( $num == 0 || $eng == 0 || $spe == 0)
    {
        exit("<script>history.go(-1);</script>");
    }*/

    $query = "select id from member where id='{$input['id']}'";
    $result = mysqli_fetch_array(mysqli_query($db,$query));
    
    if(!$result['id']){
        #$input['pw'] = hash('sha256', $input['pw'], true); 
        $query = "insert into member values('{$input['id']}','{$input['email']}', '{$input['pw']}','user')";
        mysqli_query($db,$query);
        
        exit("<script>alert(`join ok`);location.href=`/`;</script>");
    }
    else{
        exit("<script>alert(`Userid already existed`);history.go(-1);</script>");
    }
}
if($_GET['page'] == "upload"){
    session_start();
    if(!$_SESSION['id']){
        $input['id'] = mysqli_real_escape_string($db, $input['id']);
        #$input['id'] = htmlspecialchars($input['id']);
        $input['id'] = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', input['id'] );
        exit("<script>alert(`login plz`);history.go(-1);</script>");
    }
    if($_FILES['fileToUpload']['size'] >= 1024 * 1024 * 1){ exit("<script>alert(`file is too big`);history.go(-1);</script>"); } // file size limit(1MB). do not remove it.
    $extension = explode(".",$_FILES['fileToUpload']['name'])[1];
    if($extension == "txt" || $extension == "png"){
        system("cp {$_FILES['fileToUpload']['tmp_name']} ./upload/{$_FILES['fileToUpload']['name']}");
        exit("<script>alert(`upload ok`);location.href=`/`;</script>");
    }
    else{
        exit("<script>alert(`txt or png only`);history.go(-1);</script>");
    }
}
if($_GET['page'] == "download"){
    $content = file_get_contents("./upload/{$_GET['file']}");
    if(!$content){
        exit("<script>alert(`not exists file`);history.go(-1);</script>");
    }
    else{
        $content = str_replace('\\', '', $content);
        $content = str_replace('/', '', $content);
        $content = str_replace('\\\\', '', $content);
        
        header("Content-Disposition: attachment;");
        echo $content;
        exit;
    }
}
if($_GET['page'] == "admin"){
    $db = dbconnect();

    $result = mysqli_fetch_array(mysqli_query($db,"select id from member where id='{$_SESSION['id']}'"));
    if($result['id'] == "admin"){
        echo file_get_contents("/flag"); // do not remove it.
    }
    else{
        exit("<script>alert(`admin only`);history.go(-1);</script>");
    }
}

/*  this is hint. you can remove it.
CREATE TABLE `member` (
    `id` varchar(120) NOT NULL,
    `email` varchar(120) NOT NULL,
    `pw` varchar(120) NOT NULL,
    `type` varchar(5) NOT NULL
  );
  
  INSERT INTO `member` (`id`, `email`, `pw`, `type`)
      VALUES ('admin', '**SECRET**', '**SECRET**', 'admin');
*/

?>
