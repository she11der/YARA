rule SIGNATURE_BASE_Txt_Xiao : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file xiao.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "cd375597-c343-5f7d-8574-23f700ff432b"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L646-L663"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b3b98fb57f5f5ccdc42e746e32950834807903b7"
		logic_hash = "e99c307482148e4d0eb660281fa70f2dcece200ac8aed032bbef41e421d2a155"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
		$s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
		$s3 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED," ascii
		$s4 = "function Command(cmd, str){" fullword ascii
		$s5 = "echo \"if(obj.value=='PageWebProxy')obj.form.target='_blank';\"" fullword ascii

	condition:
		filesize <100KB and all of them
}
