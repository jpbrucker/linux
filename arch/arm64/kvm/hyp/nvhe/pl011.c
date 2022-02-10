// SPDX-License-Identifier: GPL-2.0
#include <kvm/pl011.h>

#include <nvhe/mm.h>

#include <linux/stdarg.h>

struct kvm_arm_pl011_device __ro_after_init *kvm_hyp_arm_pl011_device;

static struct kvm_arm_pl011_device *pl011;

static void __pkvm_pl011_write_char(char c)
{
	u32 flags;

	if (!pl011)
		return;

	do
		flags = readl_relaxed(pl011->base + PL011_FR);
	while (flags & PL011_FIFO_BUSY);

	writel_relaxed(c, pl011->base + PL011_DR);
}

static void pkvm_pl011_write_char(char c)
{
	if (c == '\n')
		__pkvm_pl011_write_char('\r');
	__pkvm_pl011_write_char(c);
}

static void pkvm_pl011_write_str(const char *str)
{
	while (*str)
		pkvm_pl011_write_char(*str++);
}

static void pkvm_pl011_write_u64(u64 val)
{
	int i;
	char digit;
	char buf[] = "0000000000000000";
	char *cur = &buf[15];

	for (i = 0; i < 16; i++) {
		digit = (val >> (i * 4)) & 0xf;
		if (!digit)
			continue;
		cur = buf + 15 - i;
		if (digit < 10)
			*cur = '0' + digit;
		else
			*cur = 'a' + digit - 10;
	}
	pkvm_pl011_write_str(cur);
}

/*
 * A very dumb printf
 * Special formats supported:
 * '%[l]*x': u64
 * '%s': char *
 */
void pkvm_pl011_printf(const char *fmt, ...)
{
	u64 q;
	char c;
	char *s;
	va_list ap;
	bool formatting = false;

	va_start(ap, fmt);
	while ((c = *fmt++) != '\0') {
		if (c == '%') {
			formatting = true;
			continue;
		}

		if (!formatting) {
			pkvm_pl011_write_char(c);
			continue;
		}

		switch (c) {
		case 'l':
			continue;
		case 'x':
			q = va_arg(ap, u64);
			pkvm_pl011_write_u64(q);
			break;
		case 's':
			s = va_arg(ap, char *);
			pkvm_pl011_write_str(s);
			break;
		default:
			pkvm_pl011_write_char('%');
			pkvm_pl011_write_char(c);
		}
		formatting = false;
	}
	va_end(ap);
}

int pkvm_pl011_init(void)
{
	int ret;
	void __iomem *base;

	if (!kvm_hyp_arm_pl011_device)
		return 0;

	ret = pkvm_create_mappings(kvm_hyp_arm_pl011_device,
				   (void *)kvm_hyp_arm_pl011_device + PAGE_SIZE,
				   PAGE_HYP);
	if (ret)
		return ret;

	ret = pkvm_create_hyp_device_mapping(kvm_hyp_arm_pl011_device->mmio_addr,
					     kvm_hyp_arm_pl011_device->mmio_size,
					     &base);
	if (ret)
		return ret;

	kvm_hyp_arm_pl011_device->base = base;
	pl011 = (void *)kvm_hyp_arm_pl011_device;

	return 0;
}
