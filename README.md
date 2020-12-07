# NSecurity 🔥

![Version](https://camo.githubusercontent.com/11c4047229b275301990437883a552b74b6377f6af0f2a5e002e908189ef9648/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f56657273696f6e2d312e302d627269676874677265656e2e7376673f6d61784167653d323539323030)

NSecurity ან NSec ან უბრალოდ #~N$3c 😂

NSecurity – Nerve Security | ვებ პლატფორმული უსაფრთხოების სისტემა (WAF) (Web Application Firewall) პროგრამული უზრუნველყოფა, რომელიც ახორციელებს, მასში შემავალი პაკეტებისა და ტრაფიკის კონტროლს და ფილტრაციას მისი მიზანია ქსელის ან ცალკეული კვანძების დაცვა არასანქცირებული წვდომისგან, 

Firewall გეხმარებათ ვებ – პროგრამების დაცვაში, ვებ – აპლიკაციასა და ინტერნეტს შორის HTTP ტრაფიკის ფილტრაციით და მონიტორინგით.ეს, როგორც წესი, იცავს ვებ პროგრამებს ისეთი შეტევებისგან, როგორიცაა

- SQL Injection (SQLi)
- Cross siite scripting (XSS)
- Local File inclusion (LFI)
- Remote File Inclusion (RFI)
- Shell Uploading
- DoS / DDoS

### NSecurity -ის პირველ ვერსიაში:

- იბლოკება მომხმარებლის მოთხოვნა
რომლებსაც არ გააჩნია User-Agent. ასევე იბლოკებიან ბოტები!

- იბლოკება ის User-Agent რომელშიც
ურევია შემდეგი სიტყვები: ```hydra, sqlmap, w3af, voideye, whatweb
wpscan, nmap, xget, wget, nikto, cisco-torch, 
arachni, cmoix, havij, sqlninja, uil2pn```

- იბლოკება ყველა SQLinjection, XSS,
RFI, LFI მცდელობა და ილოგება ფაილში ```nerve_logs``` ასევე იგზავნება [Telegram](https://telegram.org/) -ის ცჩატში შემდეგი ინფორმაცია ```შეტევის ტიპი, IP მისამართი, შეტევის თარიღი, ბრაუზერი (User-Agent) და შეტევის წერტილი```

- სურვილის შემთხვევაში იბლოკება
მომხმარებლები რომელიბიც იყენებენ TOR -ს

### გამოყენების ინსტრუქცია
პირველ რიგში უნდა შემოიტანოთ თქვენს კოდში
Firewall როგორც ეს ხდება ```/autoload.php``` ფაილში
და შემდეგ გააქტოუროთ ის მაგალითი:
```php
<?php
require_once '/controller/router.php';
$nrv = new Nerve(); // აქ თქვენ ააქტიურებთ Waf -ს
```

ასევე შევიძლიათ (სასურველია) გამოიყენოთ სისტემაში
უკვე ჩაშენბული და გამზადებული როუტერი, ამ შემთხვევაშიც
თქვენ უნდა შემოიტანოთ კოდში როუტერი
როუტერის გამართვის მაგალითი:
```php
<?php
require_once '/controller/router.php';
// საწყისი გვერდის დეკლარაციის მაგალითი
Route::add('/', function(){
  echo 'ეს არის საწყისი გვერდი';
});

// GET როუტის მაგალითი
Route::add('/contact', function(){
  echo '</h1>საკონტაქტო ფორმა</h1><form method="post"><input type="text" name="test" /><input type="submit" value="send" /></form>';
}, 'get');

// POST როუტის მაგალითი
Route::add('/contact', function(){
  print_r($_POST);
}, 'post');

// როუტი რომლითაც ვიღებთ მნიშვნელობას
// რეგექსის ფილტრაციით
Route::add('/news/([0-9]*)',function($id){
  echo 'სიახლის ID: ' . $id;
});
```
