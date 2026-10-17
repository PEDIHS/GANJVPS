"""Telegram inventory-navigation helpers. Displays only actual available slots."""
from __future__ import annotations
import html
from collections import defaultdict
from sqlalchemy import select
from app.models import Plan, PlanCatalog, CatalogLocation, Datacenter
from app.services import available_slots

FLAGS = {"DE":"🇩🇪","FR":"🇫🇷","TR":"🇹🇷","US":"🇺🇸","CA":"🇨🇦",
         "FI":"🇫🇮","NL":"🇳🇱","GB":"🇬🇧","AE":"🇦🇪","BR":"🇧🇷",
         "AR":"🇦🇷","MX":"🇲🇽","CL":"🇨🇱","CO":"🇨🇴"}
REGIONS = {
    "eu": {"DE","FR","FI","NL","GB","IT","ES","SE","NO","CH","PL","RU"},
    "asia": {"TR","AE","JP","SG","IN","HK","KR","CN","ID"},
    "america": {"US","CA","BR","AR","MX","CL","CO"},
    "africa": {"ZA","EG","KE","NG"},
    "other": set(),
}


def flagged(country: str) -> str:
    return FLAGS.get(country.upper(), "🌐")


def stock_rows(db):
    """Catalogue placements must match real hosts; never list fake inventory."""
    records = db.execute(select(Plan, PlanCatalog, CatalogLocation, Datacenter)
                         .join(PlanCatalog, PlanCatalog.plan_id == Plan.id)
                         .join(CatalogLocation, CatalogLocation.id == PlanCatalog.location_id)
                         .join(Datacenter, Datacenter.id == CatalogLocation.datacenter_id)
                         .where(Plan.enabled == True, CatalogLocation.enabled == True,
                                Datacenter.enabled == True)).all()
    items = []
    for plan, spec, loc, dc in records:
        slots = available_slots(db, plan)
        if slots:
            items.append((plan, spec, loc, dc, slots))
    return items


def render_catalog_filter(db, kind: str, code: str = "", page: int = 0):
    """Return HTML text, Telegram inline keyboard. No web UI or purchases."""
    items = stock_rows(db)
    buttons = []
    body = ""
    back = "shop"
    name = "جست‌وجوی هوشمند نود"
    if kind == "home":
        name = "انتخاب روش جست‌وجو"
        body = "سرور را بر اساس لوکیشن، دیتاسنتر یا منابع موردنیازت پیدا کن."
        buttons = [
            [("🏢 بر اساس ارائه‌دهنده / دیتاسنتر","xcat:dc")],
            [("🌍 بر اساس لوکیشن","xcat:country")],
            [("💾 حداقل RAM","xcat:ram"),("🧮 تعداد vCPU","xcat:cpu")],
            [("📈 ترافیک ماهانه","xcat:traffic")]
        ]
    elif kind == "dc":
        name = "انتخاب دیتاسنتر"
        body = "موجودی قابل سفارش هر دیتاسنتر:"
        grouping = defaultdict(set)
        labels = {}
        for plan, spec, loc, dc, slots in items:
            grouping[dc.id].update(x.id for x in slots)
            labels[dc.id] = dc.name
        buttons = [[(f"{len(grouping[k])} عدد",f"xcat:dcid:{k}"),
                    ("🏢 "+labels[k][:27],f"xcat:dcid:{k}")] for k in sorted(grouping,key=lambda i:labels[i])]
        back = "xcat:home"
    elif kind == "country":
        name = "انتخاب کشور"
        body = "کشورها و موجودی واقعی نودها:"
        grouping = defaultdict(set)
        names = {}
        for plan, spec, loc, dc, slots in items:
            grouping[loc.country_code].update(x.id for x in slots)
            names[loc.country_code] = loc.country_name
        buttons = [[(f"{len(grouping[k])} عدد",f"xcat:countryid:{k}"),
                    (f"{flagged(k)} {names[k][:27]}",f"xcat:countryid:{k}")]
                   for k in sorted(grouping,key=lambda i:names[i])]
        back = "xcat:home"
    elif kind in {"ram","cpu","traffic"}:
        name = {"ram":"حداقل RAM","cpu":"حداقل vCPU",
                "traffic":"حداقل ترافیک ماهانه"}[kind]
        body = "ابتدا حداقل منابع موردنیازت را انتخاب کن."
        if kind=="ram":
            values=[1,2,4,8,16,32]
        elif kind=="cpu":
            values=[1,2,4,8,16]
        else:
            values=[1000,2900,4900,9800]
            body += "\nترافیک نامحدود فقط پس از ثبت ظرفیت قابل‌راستی‌آزمایی نمایش داده می‌شود."
        grouping = {}
        for value in values:
            slots = set()
            for plan, spec, loc, dc, available in items:
                if kind=="ram" and spec.min_ram_mb >= value*1024:
                    slots.update(x.id for x in available)
                elif kind=="cpu" and spec.min_vcpu >= value:
                    slots.update(x.id for x in available)
                elif kind=="traffic" and spec.min_traffic_gb is not None and spec.min_traffic_gb>=value:
                    slots.update(x.id for x in available)
            grouping[value]=slots
        buttons=[]
        for value in values:
            label = f"{value} گیگابایت" if kind!="cpu" else f"{value} هسته"
            buttons.append([(f"{len(grouping[value])} عدد",f"xcat:{kind}id:{value}"),
                            (label,f"xcat:{kind}id:{value}")])
        back = "xcat:home"
    else:
        # Select matching plans. This is catalogue filtering only; purchasing
        # still validates host, region, memory, CPU and wallet atomically.
        if kind=="dcid":
            matched=[r for r in items if r[3].id==code]
            back="xcat:dc"
            name="پلن‌های دیتاسنتر"
        elif kind=="countryid":
            matched=[r for r in items if r[2].country_code==code]
            back="xcat:country"
            name="پلن‌های کشور"
        elif kind=="ramid":
            matched=[r for r in items if r[1].min_ram_mb>=int(code)*1024]
            back="xcat:ram";name="پلن‌های RAM"
        elif kind=="cpuid":
            matched=[r for r in items if r[1].min_vcpu>=int(code)]
            back="xcat:cpu";name="پلن‌های CPU"
        elif kind=="trafficid":
            matched=[r for r in items if r[1].min_traffic_gb is not None and r[1].min_traffic_gb>=int(code)]
            back="xcat:traffic";name="پلن‌های ترافیک"
        else:
            return "این دسته‌بندی موجود نیست.",[[("↩️ بازگشت","shop","danger")]]
        matched.sort(key=lambda x: (x[0].price_toman,x[0].name))
        pages=max(1,(len(matched)+4)//5)
        page=max(0,min(page,pages-1))
        listed=matched[page*5:(page+1)*5]
        body=f"پلن‌های مطابق فیلتر: {len(matched)}\nصفحه {page+1} از {pages}\n\n"
        for plan, spec, loc, dc, slots in listed:
            buttons.append([(f"{len(slots)} عدد","plan:"+plan.id),
                (f"{flagged(loc.country_code)} {plan.name[:20]} · {plan.price_toman:,} ت","plan:"+plan.id)])
        nav=[]
        prefix=f"xcat:{kind}:{code}:"
        if page>0:nav.append(("◀ قبلی",prefix+str(page-1)))
        if page+1<pages:nav.append(("بعدی ▶",prefix+str(page+1)))
        if nav:buttons.append(nav)
    if not buttons:
        body += "\nفعلاً موجودی در این دسته ثبت نشده است."
    buttons.append([("↩️ بازگشت",back,"danger"),("🏠 خانه","home")])
    text=("<b>◆ "+html.escape(name)+"</b>\n"
          "<code>GANJ VPS • NODE FINDER</code>\n"
          "━━━━━━━━━━━━━━━━\n"+html.escape(body))
    return text, buttons
