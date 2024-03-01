rule SIGNATURE_BASE_P0Wnedbinaries
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedBinaries.cs"
		author = "Florian Roth (Nextron Systems)"
		id = "0c62dd3a-195c-5890-b262-2eb00c58f8c1"
		date = "2017-01-14"
		modified = "2023-12-05"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_p0wnshell.yar#L142-L161"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4df7fcf508a9257ea418bd1995158c3676037b310dc884d44658977fda81b13b"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fd7014625b58d00c6e54ad0e587c6dba5d50f8ca4b0f162d5af3357c2183c7a7"

	strings:
		$x1 = "Oq02AB+LCAAAAAAABADs/QkW3LiOLQBuRUsQR1H731gHMQOkFGFnvvrdp/O4sp6tkDiAIIjhAryu4z6PVOtxHuXz3/xT6X9za/Df/Hsa/JT/9" ascii
		$x2 = "wpoWAB+LCAAAAAAABADs/QeyK7uOBYhORUNIenL+E2vBA0ympH3erY4f8Tte3TpbUiY9YRbcGK91vVKtr+tV3v/B/yr/m1vD/+DvNOVb+V/f" ascii
		$x3 = "mo0MAB+LCAAAAAAABADsXQl24zqu3YqXII6i9r+xJ4AACU4SZcuJnVenf/9OxbHEAcRwcQGu62NbHsrax/Iw+3/hP5b+VzuH/4WfVeDf8n98" ascii
		$x4 = "LE4CAB+LCAAAAAAABADsfQmW2zqu6Fa8BM7D/jf2hRmkKNuVm/Tt9zunkipb4giCIGb2/prhFUt5hVe+/sNP4b+pVvwPn+OQp/LT9ge/+" ascii
		$x5 = "XpMCAB+LCAAAAAAABADsfQeWIzmO6FV0hKAn73+xL3iAwVAqq2t35r/tl53VyhCDFoQ3Y7zW9Uq1vq5Xef/CT+X/59bwFz6nKU/lp+8P/" ascii
		$x6 = "STwAAB+LCAAAAAAABADtWwmy6yoO3YqXgJjZ/8ZaRwNgx/HNfX/o7qqUkxgzCM0SmLR2jHBQzkc4En9xZbvHUuSLMnWv9ateK/70ilStR" ascii
		$x7 = "namespace p0wnedShell" fullword ascii

	condition:
		1 of them
}
