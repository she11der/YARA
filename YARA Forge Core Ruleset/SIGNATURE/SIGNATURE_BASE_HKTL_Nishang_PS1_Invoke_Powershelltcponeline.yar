rule SIGNATURE_BASE_HKTL_Nishang_PS1_Invoke_Powershelltcponeline
{
	meta:
		description = "Detects PowerShell Oneliner in Nishang's repository"
		author = "Florian Roth (Nextron Systems)"
		id = "0218ebbd-2dbe-5838-ab53-1e78e3f97b9e"
		date = "2021-03-03"
		modified = "2023-12-05"
		reference = "https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_hafnium.yar#L105-L119"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "59622bff95de1077d26ee4547f37cd1045c0c1fc6817df40ff2564b33a962a07"
		score = 75
		quality = 85
		tags = ""
		hash1 = "2f4c948974da341412ab742e14d8cdd33c1efa22b90135fcfae891f08494ac32"

	strings:
		$s1 = "=([text.encoding]::ASCII).GetBytes((iex $" ascii wide
		$s2 = ".GetStream();[byte[]]$" ascii wide
		$s3 = "New-Object Net.Sockets.TCPClient('" ascii wide

	condition:
		all of them
}