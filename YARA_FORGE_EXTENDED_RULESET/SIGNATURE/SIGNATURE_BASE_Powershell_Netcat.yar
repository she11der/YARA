import "pe"

rule SIGNATURE_BASE_Powershell_Netcat
{
	meta:
		description = "Detects a Powershell version of the Netcat network hacking tool"
		author = "Florian Roth (Nextron Systems)"
		id = "e4b018c0-3214-5102-93b1-6a048324f9dd"
		date = "2014-10-10"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L569-L583"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ff9d7c3e83fd27620559306c07556ce7afd1ba7a5db5f5c21ad0841d58b85014"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "[ValidateRange(1, 65535)]" fullword
		$s1 = "$Client = New-Object -TypeName System.Net.Sockets.TcpClient" fullword
		$s2 = "$Buffer = New-Object -TypeName System.Byte[] -ArgumentList $Client.ReceiveBufferSize" fullword

	condition:
		all of them
}
