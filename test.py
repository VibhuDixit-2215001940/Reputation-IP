import os,requests,json,sys,ipaddress
from datetime import datetime
from dotenv import load_dotenv
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
from reportlab.lib.styles import getSampleStyleSheet
load_dotenv()
ABUSE_KEY=os.getenv("ABUSE_KEY")
VT_KEY=os.getenv("VT_KEY")
SHODAN_KEY=os.getenv("SHODAN_KEY")
def abuse(ip):
    try:
        r=requests.get("https://api.abuseipdb.com/api/v2/check",params={"ipAddress":ip},headers={"Key":ABUSE_KEY,"Accept":"application/json"},timeout=10)
        print("AbuseIPDB:",r.status_code)
        return r.json().get("data",{}) if r.status_code==200 else {"_status":r.status_code,"_text":r.text[:200]}
    except Exception as e:
        return {"_error":str(e)}
def vt(ip):
    try:
        r=requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",headers={"x-apikey":VT_KEY},timeout=10)
        print("VirusTotal:",r.status_code)
        return r.json().get("data",{}) if r.status_code==200 else {"_status":r.status_code,"_text":r.text[:200]}
    except Exception as e:
        return {"_error":str(e)}
def shodan(ip):
    try:
        r=requests.get(f"https://api.shodan.io/shodan/host/{ip}",params={"key":SHODAN_KEY},timeout=10)
        print("Shodan:",r.status_code)
        return r.json() if r.status_code==200 else {"_status":r.status_code,"_text":r.text[:200]}
    except Exception as e:
        return {"_error":str(e)}
def score_ip(ip):
    private=ipaddress.ip_address(ip).is_private
    a=abuse(ip);v=vt(ip);s=shodan(ip)
    abuse_score=min(1,(a.get("totalReports",0)/50)) if isinstance(a,dict) else 0
    vt_score=min(1,(v.get("attributes",{}).get("last_analysis_stats",{}).get("malicious",0)/10)) if isinstance(v,dict) else 0
    ports=0
    if isinstance(s,dict):
        if isinstance(s.get("data",None),list): ports=len(s.get("data",[]))
        else: ports=len(s.get("ports",[])) if s.get("ports") else 0
    port_score=min(1,ports/10)
    sc=100*(0.4*abuse_score+0.2*vt_score+0.15*port_score)
    return {"ip":ip,"score":round(sc,2),"private":private,"abuse":a,"vt":{"attributes":v} if v else {}, "shodan":s}
def save_json(result):
    fn=f"ip_report_{result['ip']}.json"
    with open(fn,"w") as f: json.dump(result,f,indent=2)
    print("✅ JSON saved:",fn)
    return fn
def make_table(data_dict):
    rows=[["Field","Value"]]
    for k,v in data_dict.items():
        val=json.dumps(v) if isinstance(v,(dict,list)) else str(v)
        rows.append([k,val])
    t=Table(rows,colWidths=[2.2*inch,4.3*inch])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#007ACC")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("ALIGN",(0,0),(-1,-1),"LEFT"),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,0),11),("BOTTOMPADDING",(0,0),(-1,0),6),("BACKGROUND",(0,1),(-1,-1),colors.whitesmoke),("GRID",(0,0),(-1,-1),0.3,colors.grey)]))
    return t
def save_pdf(result):
    ip=result["ip"];score=result["score"]
    doc=SimpleDocTemplate(f"ip_report_{ip}.pdf",pagesize=A4)
    styles=getSampleStyleSheet()
    elements=[]
    def add_hdr(t): elements.append(Paragraph(f"<font size=16 color='#007ACC'><b>{t}</b></font>",styles["BodyText"])); elements.append(Spacer(1,0.2*inch))
    def add_sub(t): elements.append(Paragraph(f"<b>{t}</b>",styles["Heading3"])); elements.append(Spacer(1,0.1*inch))
    add_hdr("🧠 IP Reputation Report")
    elements.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",styles["Normal"]))
    elements.append(Paragraph(f"<b>IP Address:</b> {ip}<br/><b>Overall Score:</b> {score} / 100",styles["Normal"]))
    elements.append(Spacer(1,0.2*inch))
    add_sub("⚙️ 1. AbuseIPDB Results")
    elements.append(make_table(result["abuse"] or {"note":"No data"})); elements.append(Spacer(1,0.2*inch))
    add_sub("🧬 2. VirusTotal Results")
    elements.append(make_table(result["vt"].get("attributes",{}) or {"note":"No data"})); elements.append(Spacer(1,0.2*inch))
    add_sub("🌐 3. Shodan Results")
    elements.append(make_table(result["shodan"] or {"note":"No data"})); elements.append(Spacer(1,0.2*inch))
    add_sub("📊 4. Scoring Breakdown")
    rows=[["Source","Sub-Score","Weight","Contribution"],["AbuseIPDB",f"{result['abuse'].get('totalReports',0)} reports","0.4",f"{round(result['score']*0.4/100,2)}"],["VirusTotal","malicious stats","0.2",f"{round(result['score']*0.2/100,2)}"],["Shodan","open ports","0.15",f"{round(result['score']*0.15/100,2)}"]]
    t=Table(rows,colWidths=[2*inch,1.8*inch,1.3*inch,1.4*inch])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#444444")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("BACKGROUND",(0,1),(-1,-1),colors.beige),("GRID",(0,0),(-1,-1),0.3,colors.grey)]))
    elements.append(t); elements.append(Spacer(1,0.2*inch))
    add_sub("🧾 5. Final Verdict")
    verdict="🟢 Safe / Internal IP (RFC1918)" if result["private"] else "🔍 Public IP — Analyzed"
    elements.append(Paragraph(f"<b>Verdict:</b> {verdict}",styles["Normal"]))
    doc.build(elements)
    print("✅ PDF saved: ip_report_%s.pdf" % ip)
if __name__=="__main__":
    if len(sys.argv)<2:
        print("Usage: python test.py <ip_address>")
        sys.exit(1)
    if not ABUSE_KEY or not VT_KEY or not SHODAN_KEY:
        print("Error: Missing API keys. Check .env file and that keys are set in environment.")
        print("ABUSE_KEY present:", bool(ABUSE_KEY),"VT_KEY present:", bool(VT_KEY),"SHODAN_KEY present:", bool(SHODAN_KEY))
        sys.exit(1)
    ip=sys.argv[1]
    print("Running scan for",ip)
    result=score_ip(ip)
    save_json(result)
    save_pdf(result)
    print(json.dumps(result,indent=2))
