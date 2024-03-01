rule MALPEDIA_Win_Nautilus_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "bd0f8568-9347-5c4b-aef6-8e7929cf6017"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nautilus"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.nautilus_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "6e0983236c8ba852bb2af3aa295c07b825fa6ac12512321743324e3ea59238a7"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 8bcf e8???????? 8bd8 8bcd e8???????? 85db 8bce }
		$sequence_1 = { 85c0 740c 488b4598 4833c7 e9???????? c74424200f000000 e9???????? }
		$sequence_2 = { 8bfe 486313 488d0dcc340600 f6040a02 744b 418d46fa 488bcb }
		$sequence_3 = { 85c0 7892 488d4c2430 498bd4 e8???????? 85c0 7981 }
		$sequence_4 = { ba03000000 4d8bc5 8d4aff e8???????? 4c8be0 4885c0 7509 }
		$sequence_5 = { 85f6 750c 33c0 eb3a 488b0b 49890e eb30 }
		$sequence_6 = { 85c0 79d6 4c8d45cf 488d55cf 488d4db7 e8???????? 8bd8 }
		$sequence_7 = { eb07 c745e006000000 488d45e0 41b912000000 4d8bc4 498bd5 488bcf }
		$sequence_8 = { 4883f803 0f8cef010000 488bd3 488bcd ff95c8010000 85c0 0f8599feffff }
		$sequence_9 = { e8???????? 85c0 7531 488d4db0 33d2 e8???????? 85c0 }

	condition:
		7 of them and filesize <1302528
}
