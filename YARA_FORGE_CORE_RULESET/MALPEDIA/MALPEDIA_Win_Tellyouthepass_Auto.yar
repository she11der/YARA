rule MALPEDIA_Win_Tellyouthepass_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "2f59ff80-ce55-5261-bc1e-9b9085ba348c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tellyouthepass"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.tellyouthepass_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "e0931a30828c9c1e2a42766d85093d9ba189ed49cc692d748a9e549b96d308d1"
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
		$sequence_0 = { 4c895c2438 48895c2430 e8???????? 488d05e4021a00 bb1d000000 e8???????? 488b442450 }
		$sequence_1 = { 488d05a4bf1700 bb13000000 0f1f440000 e8???????? 8b442414 89c0 e8???????? }
		$sequence_2 = { e8???????? 488b442428 e8???????? 488d0509dd1700 bb07000000 e8???????? 488b442420 }
		$sequence_3 = { e9???????? 488d05231a3400 31db 488b6c2458 4883c460 c3 48895c2470 }
		$sequence_4 = { 7506 48894208 eb09 488d7a08 e8???????? 488bac24f8000000 4881c400010000 }
		$sequence_5 = { c3 440fb6ac24080a0000 4584ed 0f8471030000 4983fc07 0f85aa010000 4c8b4828 }
		$sequence_6 = { e8???????? e8???????? 488b4818 488b5820 488b5028 4889c8 4889d1 }
		$sequence_7 = { 498d7a78 e8???????? 498b9050010000 498b9858010000 498bb060010000 49899a98000000 4989b2a0000000 }
		$sequence_8 = { 84c0 0f8566feffff 31c0 488b6c2418 4883c420 c3 31c0 }
		$sequence_9 = { 0f1f00 e8???????? 31db 31c9 488d3d501c0c00 4889c6 31c0 }

	condition:
		7 of them and filesize <7152640
}
