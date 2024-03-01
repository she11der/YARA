rule SIGNATURE_BASE_Reduhservers_Reduh_2 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file reDuh.php"
		author = "Florian Roth (Nextron Systems)"
		id = "6050dfde-6c79-5dd8-a772-508668177aa5"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L191-L206"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "512d0a3e7bb7056338ad0167f485a8a6fa1532a3"
		logic_hash = "954115da374b6d72c35244673799be6e8bae5288f53509dea04e3ae3c489af12"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "errorlog(\"FRONTEND: send_command '\".$data.\"' on port \".$port.\" returned \"." ascii
		$s2 = "$msg = \"newData:\".$socketNumber.\":\".$targetHost.\":\".$targetPort.\":\".$seq" ascii
		$s3 = "errorlog(\"BACKEND: *** Socket key is \".$sockkey);" fullword ascii

	condition:
		filesize <57KB and all of them
}
