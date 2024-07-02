namespace RSA;

interface

uses
  System,
  System.Text,
  System.Security.Cryptography;

type
  Program = class
  public
    class method Main(args: array of String);
    class method GenerateKeys(out publicKey: String; out privateKey: String);
    class method SHA256Hash(Input: String): String;
    class method FindPOW(Nickname: String): String;
    class method SignData(data: String; privateKey: String): String;
    class method VerifySignature(data: String; signature: String; publicKey: String): Boolean;
  end;

implementation

class method Program.GenerateKeys(out publicKey: String; out privateKey: String);
begin
  using rsa := RSA.Create do
  begin
    publicKey := Convert.ToBase64String(rsa.ExportRSAPublicKey);
    privateKey := Convert.ToBase64String(rsa.ExportRSAPrivateKey);
  end;
end;

class method Program.SHA256Hash(Input: String): String;
begin
  using sha256 := SHA256.Create do
  begin
    var bytes := Encoding.UTF8.GetBytes(Input);
    var hashBytes := sha256.ComputeHash(bytes);
    var sb := new StringBuilder;
    for each b in hashBytes do
      sb.AppendFormat('{0:x2}', [b]);
    exit sb.ToString;
  end;
end;

class method Program.FindPOW(Nickname: String): String;
begin
  var nonce := 0;
  var startTime := DateTime.Now;

  repeat
    var hash := SHA256Hash(Nickname + nonce.ToString);
    if hash.StartsWith('0000') then
    begin
      var endTime := DateTime.Now;
      var elapsedTime := (endTime - startTime).TotalSeconds;
      exit String.Format('Nonce: {0}' + Environment.NewLine + 'Hash: {1}' + Environment.NewLine + 'Time: {2} seconds', [nonce, hash, elapsedTime]);
    end;
    inc(nonce);
  until false;
end;

class method Program.SignData(data: String; privateKey: String): String;
begin
  using rsa := RSA.Create do
  begin
    rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out var _);
    var dataBytes := Encoding.UTF8.GetBytes(data);
    var signedBytes := rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    exit Convert.ToBase64String(signedBytes);
  end;
end;

class method Program.VerifySignature(data: String; signature: String; publicKey: String): Boolean;
begin
  using rsa := RSA.Create do
  begin
    rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out var _);
    var dataBytes := Encoding.UTF8.GetBytes(data);
    var signatureBytes := Convert.FromBase64String(signature);
    exit rsa.VerifyData(dataBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
  end;
end;

class method Program.Main(args: array of String);
begin
  var nickname := 'rocky';

  // 生成公私钥对
  var publicKey, privateKey: String;
  GenerateKeys(out publicKey, out privateKey);
  Console.WriteLine('Public Key: ' + publicKey);
  Console.WriteLine('Private Key: ' + privateKey);

  // 执行 PoW
  var powResult := FindPOW(nickname);
  Console.WriteLine(powResult);

  // 签名 PoW 结果
  var signature := SignData(powResult, privateKey);
  Console.WriteLine('Signature: ' + signature);

  // 验证签名
  var isValid := VerifySignature(powResult, signature, publicKey);
  Console.WriteLine('Signature is valid: ' + isValid.ToString);
end;

end.