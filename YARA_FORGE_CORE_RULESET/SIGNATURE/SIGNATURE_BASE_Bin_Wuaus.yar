rule SIGNATURE_BASE_Bin_Wuaus
{
	meta:
		description = "Webshells Auto-generated - file wuaus.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "50b5323b-d8d1-5350-bf93-8dde3d11fd87"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8819-L8835"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "46a365992bec7377b48a2263c49e4e7d"
		logic_hash = "0509ca39662430c3ababf65ca3a6e9af95250163980829d90eddf5341168c864"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "9(90989@9V9^9f9n9v9"
		$s2 = ":(:,:0:4:8:C:H:N:T:Y:_:e:o:y:"
		$s3 = ";(=@=G=O=T=X=\\="
		$s4 = "TCP Send Error!!"
		$s5 = "1\"1;1X1^1e1m1w1~1"
		$s8 = "=$=)=/=<=Y=_=j=p=z="

	condition:
		all of them
}
