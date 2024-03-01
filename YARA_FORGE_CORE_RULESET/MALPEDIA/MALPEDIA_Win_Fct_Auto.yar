rule MALPEDIA_Win_Fct_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "2b1f29a9-1362-5741-a18b-c3a100da706f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fct"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.fct_auto.yar#L1-L127"
		license_url = "N/A"
		logic_hash = "d2be9c8f676646ff8bb82d16a11f73bdaff1325b5ad55ea7931b7cc2d022d940"
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
		$sequence_0 = { 83e801 0f8595010000 c745e438324100 e9???????? 894de0 c745e438324100 e9???????? }
		$sequence_1 = { c3 c705????????80554100 b001 c3 68???????? e8???????? c70424???????? }
		$sequence_2 = { e9???????? 8b1f 8d049d58634100 8b30 }
		$sequence_3 = { 8bc6 83e03f 6bc838 894de0 8b049d50614100 f644082801 7469 }
		$sequence_4 = { 6a04 e8???????? 83bd48fdffff08 8d8d34fdffff 8d45d8 }
		$sequence_5 = { c70021000000 eb44 c745e002000000 c745e444324100 8b4508 8bcf 8b7510 }
		$sequence_6 = { 50 8b04bd50614100 ff743018 ff15???????? 85c0 7404 b001 }
		$sequence_7 = { 56 33f6 8b8650614100 85c0 740e 50 e8???????? }
		$sequence_8 = { 660fd60f 8d7f08 8b048d84514000 ffe0 f7c703000000 7413 }
		$sequence_9 = { 68???????? c68524fdffff00 8d4dd8 ffb524fdffff 6a01 e8???????? }

	condition:
		7 of them and filesize <204800
}
