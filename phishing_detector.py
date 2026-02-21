import streamlit as st
import re
from urllib.parse import urlparse
import datetime
import whois
import plotly.graph_objects as go


def analyze_url(url):
    score = 0
    details = {}


    length = len(url)
    if length < 30: length_score = 5
    elif length < 50: length_score = 10
    else: length_score = 20
    score += length_score
    details['URL Length'] = length_score


    try:
        hostname = urlparse(url).hostname
        if re.match(r"\d+\.\d+\.\d+\.\d+", hostname):
            ip_score = 20
        else:
            ip_score = 0
    except:
        ip_score = 10
    score += ip_score
    details['IP in URL'] = ip_score


    suspicious_words = ['login', 'secure', 'update', 'verify', 'bank', 'account', 'confirm']
    word_score = sum(10 for word in suspicious_words if word in url.lower())
    score += word_score
    details['Suspicious Words'] = word_score

    # HTTPS
    https_score = 0 if url.startswith('https://') else 15
    score += https_score
    details['HTTPS'] = https_score

    
    try:
        domain_info = whois.whois(hostname)
        if domain_info.creation_date:
            if isinstance(domain_info.creation_date, list):
                domain_age = (datetime.datetime.now() - domain_info.creation_date[0]).days
            else:
                domain_age = (datetime.datetime.now() - domain_info.creation_date).days
            if domain_age < 180:
                age_score = 15
            else:
                age_score = 0
        else:
            age_score = 10
    except:
        age_score = 10
    score += age_score
    details['Domain Age'] = age_score

    if score > 100: score = 100
    return score, details


st.set_page_config(page_title="Phishing Link Detector", layout="centered")
st.title("Phishing Link Detector")


url_input = st.text_input("Enter URL:")

if st.button("Analyze"):
    if url_input:
        risk_score, detail_scores = analyze_url(url_input)

        
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = risk_score,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Risk Score"},
            gauge = {
                'axis': {'range': [0,100]},
                'bar': {'color': "red" if risk_score>70 else "orange" if risk_score>30 else "green"},
                'steps': [
                    {'range': [0,30], 'color': "green"},
                    {'range': [30,70], 'color': "orange"},
                    {'range': [70,100], 'color': "red"}]
            }
        ))
        st.plotly_chart(fig, use_container_width=True)

       
        st.subheader(" Analysis Details:")
        for k, v in detail_scores.items():
            icon = "V" if v==0 else "X"
            st.write(f"{icon} **{k}**: {v} points")

        
        if risk_score < 30:
            st.success(" le lien est sécurisé")
        elif risk_score < 70:
            st.warning(" le lien est douteux")
        else:
            st.error(" le lien est extrêmement dangereux")
    else:
        st.error("s'il vous plaît entrer une URL valide")