rule MALPEDIA_Win_Tor_Loader_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a70795d3-ed07-58b1-af1f-1705de4529bb"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tor_loader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.tor_loader_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "5d8db358e57884a4955f1fc346221e8831cd43555daaec59fcf000e4dc8835e4"
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
		$sequence_0 = { eb29 488d7a38 e8???????? 4889df 488b4c2440 6690 e8???????? }
		$sequence_1 = { eb15 4c8d8f88000000 4889f8 4c89cf e8???????? 4889c7 488b4740 }
		$sequence_2 = { e8???????? 48c7400810000000 488d0da0490c00 488908 833d????????00 6690 7509 }
		$sequence_3 = { eb0c 41bc00000000 41bb00000000 0f8573feffff 4c8bac2480000000 4883bc248800000004 0f855cfeffff }
		$sequence_4 = { e9???????? 4c89542478 4983f901 7560 488d05a10e1900 bb01000000 4889d9 }
		$sequence_5 = { e8???????? 833d????????00 750e 488b8c24800d0000 48894818 eb11 488d7818 }
		$sequence_6 = { e8???????? 488d05ca2e1300 e8???????? 48c7400826000000 488d0d358f1800 488908 4889c3 }
		$sequence_7 = { e8???????? 488d05dc0e3100 bb04000000 e8???????? 488b8424d0000000 e8???????? 488d050b203100 }
		$sequence_8 = { eb38 488b8c24c0020000 488b11 488b4238 6690 e8???????? 83f001 }
		$sequence_9 = { e8???????? 48895c2450 4889c1 488d053fe00500 4889cb e8???????? 488b5c2450 }

	condition:
		7 of them and filesize <13050880
}