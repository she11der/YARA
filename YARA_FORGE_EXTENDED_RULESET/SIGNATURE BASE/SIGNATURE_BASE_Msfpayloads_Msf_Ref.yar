rule SIGNATURE_BASE_Msfpayloads_Msf_Ref
{
	meta:
		description = "Metasploit Payloads - file msf-ref.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "517ed365-03c6-5563-984b-dae10464671a"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_metasploit_payloads.yar#L304-L323"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ed6e408575b88ff67479ac1b1a2f37c5fad3ec200a446700840ad4245386bfc4"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4ec95724b4c2b6cb57d2c63332a1dd6d4a0101707f42e3d693c9aab19f6c9f87"

	strings:
		$s1 = "kernel32.dll WaitForSingleObject)," ascii
		$s2 = "= ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')" ascii
		$s3 = "GetMethod('GetProcAddress').Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object" ascii
		$s4 = ".DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual'," ascii
		$s5 = "= [System.Convert]::FromBase64String(" ascii
		$s6 = "[Parameter(Position = 0, Mandatory = $True)] [Type[]]" fullword ascii
		$s7 = "DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard," ascii

	condition:
		5 of them
}
