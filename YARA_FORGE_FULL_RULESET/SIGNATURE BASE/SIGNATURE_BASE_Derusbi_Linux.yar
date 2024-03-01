rule SIGNATURE_BASE_Derusbi_Linux : FILE
{
	meta:
		description = "Derusbi Server Linux version"
		author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
		id = "2b33afb5-be87-5d41-b05e-b99d0c1d8ed9"
		date = "2015-12-09"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_derusbi.yar#L24-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "68d5af17b33d1aa0388516e5d2a1ad29c22dc04451e232dfbdf1ef0714baeb10"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$PS1 = "PS1=RK# \\u@\\h:\\w \\$"
		$cmd = "unset LS_OPTIONS;uname -a"
		$pname = "[diskio]"
		$rkfile = "/tmp/.secure"
		$ELF = "\x7fELF"

	condition:
		$ELF at 0 and $PS1 and $cmd and $pname and $rkfile
}
