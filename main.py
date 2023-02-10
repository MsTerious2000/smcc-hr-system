from flask import Flask, session, render_template, redirect, url_for, g, jsonify, request, abort
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from pip._vendor import cachecontrol
import google.auth.transport.requests

import requests
import sqlite3 as sqlite
from twilio.rest import Client
from datetime import date
import os
import pathlib

client = Client("ACeedfe773d77c39f6725bc24ffe9531cd","f2702378ff5c895668b3e1bd19f2039e")

app = Flask(__name__)

app.secret_key = 'secret'
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "201166069775-evuh1ih66a1qdn2vv57h31vad6r2qo59.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
		client_secrets_file=client_secrets_file,
		scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
		redirect_uri="https://smcc-hr-system.onrender.com/callback"
	)

@app.before_request
def conn():
    g.conn = sqlite.connect("HR.db")
    g.cur = g.conn.cursor()

def send_sms(number, message):
	payload = {'to':number,'message': message}
	r = requests.post('http://192.167.1.100:1688/services/api/messaging', params=payload)
	print(r.text)
	return 'Success'

def login_is_required(function):
	def wrapper(*args, **kwargs):
		if "google_id" not in session:
			return abort(401) # need login
		else:
			return function()
	return wrapper

@app.route("/protected_area")
@login_is_required
def protected_area():
    return f"Hello {session['name']}! <br/> <a href='/logouts'><button>Logout</button></a>"

@app.route("/callback")
def callback():

	flow.fetch_token(authorization_response=request.url)

	if not session["state"] == request.args["state"]:
		abort(500)  # invalid

	credentials = flow.credentials
	request_session = requests.session()
	cached_session = cachecontrol.CacheControl(request_session)
	token_request = google.auth.transport.requests.Request(session=cached_session)

	id_info = id_token.verify_oauth2_token(
		id_token=credentials.id_token,
		request=token_request,
		audience=GOOGLE_CLIENT_ID
	)
	sql = "SELECT * FROM accounts LEFT JOIN employee_info ON accounts.id = employee_info.id WHERE email='{}'".format(id_info.get("email"))
	print(sql)
	g.cur.execute(sql)
	data = g.cur.fetchall()
	if(len(data) > 0):
		session['log'] = data[0]
		return redirect(url_for("index"))
	else:
		return redirect(url_for("login_error"))
		
	# return id_info
	# session["google_id"] = id_info.get("sub")
	# session["name"] = id_info.get("name")
	# return redirect("/protected_area")

@app.route("/login_error")
def login_error():
	return render_template("login_error.html")

@app.route("/login_with_google")
def login_with_google():
	authorization_url, state = flow.authorization_url()
	session["state"] = state
	return redirect(authorization_url)

@app.route("/")
def index():
	if "log" not in session:
		return redirect(url_for("login"))
	info = session['log']

	year = date.today().year 

	sql = "SELECT * FROM leave_days WHERE user_id = '{}' and year = '{}'".format(info[0],year)
	g.cur.execute(sql)
	remaining_leave = g.cur.fetchall()
	
	pending = getPendingRequestsCount('travel_order_form', session['log'][5])
	approve = getPendingRequestsCount('travel_order_form', 'APPROVED')
	disapprove = getPendingRequestsCount('travel_order_form', 'DISAPPROVED')

	pending_leave = getPendingRequestsCount('leave_form', session['log'][5])
	approve_leave = getPendingRequestsCount('leave_form', 'APPROVED')
	disapprove_leave = getPendingRequestsCount('leave_form', 'DISAPPROVED')

	pending_overtime = getPendingRequestsCount('overtime_authorization', session['log'][5])
	approve_overtime = getPendingRequestsCount('overtime_authorization', 'APPROVED')
	disapprove_overtime = getPendingRequestsCount('overtime_authorization', 'DISAPPROVED')
	# travel = getTravelForms(session['log'][5])
	# overtime = getOvertimeForms(session['log'][5])
	
	if session['log'][5] == "PMO":
		return render_template("PMO/index.html", info=info, pending=pending, approve=approve, disapprove=disapprove,remaining_leave=remaining_leave)
	elif session['log'][5] == "DH":
		return render_template("DH/index.html", info=info, pending=pending, approve=approve, disapprove=disapprove, 
						pending_leave=pending_leave, approve_leave=approve_leave, disapprove_leave=disapprove_leave, pending_overtime=pending_overtime, 
						approve_overtime=approve_overtime, disapprove_overtime=disapprove_overtime,remaining_leave=remaining_leave)
	elif session['log'][5] == "HHRD":
		return render_template("HHRD/index.html", info=info, pending=pending, approve=approve, disapprove=disapprove, pending_leave=pending_leave, 
						approve_leave=approve_leave, disapprove_leave=disapprove_leave, pending_overtime=pending_overtime, 
						approve_overtime=approve_overtime, disapprove_overtime=disapprove_overtime, remaining_leave=remaining_leave)
	elif session['log'][5] == "VP":
		return render_template("VP/index.html", info=info, pending=pending, approve=approve, disapprove=disapprove, remaining_leave=remaining_leave)
	elif session['log'][5] == "VP-ADMIN":
		return render_template("VP-ADMIN/index.html", info=info, pending=pending, approve=approve, disapprove=disapprove, remaining_leave=remaining_leave)
	elif session['log'][5] == "SP":
		return render_template("SP/index.html", info=info, pending_leave=pending_leave, approve_leave=approve_leave, disapprove_leave=disapprove_leave,remaining_leave=remaining_leave)
	elif session['log'][5] == "EMPLOYEE":
		return render_template("employee/index.html",info=info,remaining_leave=remaining_leave)
	else:
		sql = "SELECT count(*) FROM accounts"
		g.cur.execute(sql)
		users = g.cur.fetchall()[0]
		
		sql = "SELECT count(*) FROM travel_order_form"
		g.cur.execute(sql)
		travel = g.cur.fetchall()[0]
		
		sql = "SELECT count(*) FROM leave_form"
		g.cur.execute(sql)
		leave = g.cur.fetchall()[0]
		
		sql = "SELECT count(*) FROM overtime_authorization"
		g.cur.execute(sql)
		overtime = g.cur.fetchall()[0]

		return render_template("index.html", users=users, travel=travel, leave=leave, overtime=overtime)

# ----------------------------------- PMO ------------------------------------------- #

@app.route("/pmo")
def pmo():
	if "log" not in session:
		return redirect(url_for("login"))
	
	return redirect(url_for('index'))

@app.route("/view_pmo_travel_order_forms")
def view_pmo_travel_order_forms():
	info = session['log']
	data = getTravelForms(session['log'][5])

	return render_template("PMO/display_travel_order_request.html",data=data,info=info)

@app.route("/pmo_view_travel_order_form/<int:id>")
def pmo_view_travel_order_form(id):
	info = session['log']
	data = getTravelFormData(id)
	
	return render_template("PMO/view_travel_order_form.html",data=data,info=info)

@app.route("/pmo_approve_travel_order_form/<int:id>",methods=['POST'])
def pmo_approve_travel_order_form(id):
	vehicle_pass = request.form['vehicle_pass']
	vehicle = request.form['vehicle']
	approved_by = request.form['approved_by']
	driver = request.form['driver']

	sql = "UPDATE travel_order_form SET vehicle_pass='{}', vehicle='{}', approved_by='{}', driver='{}', status='DH' WHERE id='{}'".format(vehicle_pass,vehicle,approved_by,driver,id)
	g.cur.execute(sql)
	g.conn.commit()

	sql = "SELECT user_id FROM travel_order_form WHERE id='{}'".format(id)
	g.cur.execute(sql)
	user_id = g.cur.fetchall()[0][0]

	sql = "SELECT contact FROM employee_info WHERE id='{}'".format(user_id)
	g.cur.execute(sql)
	contact = g.cur.fetchall()[0][0]
	
	_message = "Travel Order Approved by PMO. Forwarded to Department Head."
	send_sms(contact, _message)

	_message = "Pending Travel Order awaiting approval."
	sendGroupSMS(_message, 'DH')

	return jsonify({'data': 'success', 'route': 'view_pmo_travel_order_forms'})
	# return redirect(url_for("view_pmo_travel_order_forms"))

# ----------------------------------- END PMO ------------------------------------------- #

# ----------------------------------- DEPARTMENT HEAD ------------------------------------------- #

@app.route("/dh")
def dh():
	if "log" not in session:
		return redirect(url_for("login"))
	return redirect(url_for('index'))

@app.route("/view_dh_travel_order_forms")
def view_dh_travel_order_forms():
	info = session['log']
	data = getTravelForms(session['log'][5])

	return render_template("DH/display_travel_order_request.html",data=data,info=info)
	
@app.route("/dh_view_travel_order_form/<int:id>")
def dh_view_travel_order_form(id):
	info = session['log']

	data = getTravelFormData(id)
	dh = getDH(info[11])
	hhrd = getSignatory('HHRD')
	vp = getSignatory('VP')
	return render_template("DH/view_travel_order_form.html",data=data,info=info, dh=dh, hhrd=hhrd, vp=vp)

@app.route("/dh_approve_travel_order_form/<int:id>",methods=['POST'])
def dh_approve_travel_order_form(id):
	department_head = request.form['department_head']

	sql = "UPDATE travel_order_form SET department_head='{}', status='HHRD' WHERE id='{}'".format(department_head,id)
	g.cur.execute(sql)
	g.conn.commit()

	sql = "SELECT user_id FROM travel_order_form WHERE id='{}'".format(id)
	g.cur.execute(sql)
	user_id = g.cur.fetchall()[0][0]

	sql = "SELECT contact FROM employee_info WHERE id='{}'".format(user_id)
	g.cur.execute(sql)
	contact = g.cur.fetchall()[0][0]
	
	_message = "Travel Order Approved by Head. Forwarded to Human Resource Department."
	send_sms(contact, _message)

	_message = "Pending Travel Order awaiting approval."
	sendGroupSMS(_message, 'HHRD')
	return jsonify({'data': 'success', 'route': 'view_dh_travel_order_forms'})

@app.route("/view_dh_leave_forms")
def view_dh_leave_forms():
	info = session['log']
	data = getLeaveForms(session['log'][5])
	return render_template("DH/display_leave_forms.html",data=data,info=info)

@app.route("/dh_view_leave_form/<int:id>")
def dh_view_leave_form(id):
	info = session['log']
	data = getLeaveFormData(id)
	return render_template("DH/view_leave_form.html",data=data,info=info)

@app.route("/dh_approve_leave_form/<int:id>",methods=['POST'])
def dh_approve_leave_form(id):
	department_head = request.form['department_head']
	sql = "UPDATE leave_form SET department_head='{}', status='HHRD' WHERE id='{}'".format(department_head,id)
	g.cur.execute(sql)
	g.conn.commit()

	sql = "SELECT user_id FROM leave_form WHERE id='{}'".format(id)
	g.cur.execute(sql)
	user_id = g.cur.fetchall()[0][0]

	sql = "SELECT contact FROM employee_info WHERE id='{}'".format(user_id)
	g.cur.execute(sql)
	contact = g.cur.fetchall()[0][0]

	_message = "Leave Form Approved by Head. Forwarded to Human Resource Department."
	send_sms(contact, _message)

	_message = "Pending Leave Form awaiting approval."
	sendGroupSMS(_message, 'HHRD')
	
	return jsonify({'data': 'success', 'route': 'view_dh_leave_forms'})

@app.route("/view_dh_overtime_authorizations")
def view_dh_overtime_authorizations():
	info = session['log']
	data = getOvertimeForms(session['log'][5])
	return render_template("DH/display_overtime_authorizations.html",data=data,info=info)

@app.route("/dh_view_overtime_authorization/<int:id>")
def dh_view_overtime_authorization(id):
	info = session['log']
	data = getOvertimeFormData(id)
	return render_template("DH/view_overtime_authorization.html",data=data,info=info)

@app.route("/dh_approve_overtime_authorization/<int:id>",methods=['POST'])
def dh_approve_overtime_authorization(id):
	department_head = request.form['department_head']

	sql = "UPDATE overtime_authorization SET department_head='{}', status='HHRD' WHERE id='{}'".format(department_head,id)
	g.cur.execute(sql)
	g.conn.commit()

	sql = "SELECT user_id FROM overtime_authorization WHERE id='{}'".format(id)
	g.cur.execute(sql)
	user_id = g.cur.fetchall()[0][0]

	sql = "SELECT contact FROM employee_info WHERE id='{}'".format(user_id)
	g.cur.execute(sql)
	contact = g.cur.fetchall()[0][0]

	_message = "Overtime Authorization Approved by Head. Forwarded to Human Resource Department."
	send_sms(contact, _message)

	_message = "Pending Overtime Authorization awaiting approval."
	sendGroupSMS(_message, 'HHRD')

	return jsonify({'data': 'success', 'route': 'view_dh_overtime_authorizations'})

# ----------------------------------- END DEPARTMENT HEAD ------------------------------------------- #

# ----------------------------------- HHRD ------------------------------------------- #

@app.route("/view_hhrd_travel_order_forms")
def view_hhrd_travel_order_forms():
	info = session['log']
	data = getTravelForms(session['log'][5])
	return render_template("HHRD/display_travel_order_request.html",data=data,info=info)

@app.route("/hhrd_view_travel_order_form/<int:id>")
def hhrd_view_travel_order_form(id):
	info = session['log']
	data = getTravelFormData(id)
	return render_template("HHRD/view_travel_order_form.html",data=data,info=info)

@app.route("/hhrd_approve_travel_order_form/<int:id>",methods=['POST'])
def hhrd_approve_travel_order_form(id):
	head_human_resource_department = request.form['head_human_resource_department']

	sql = "SELECT user_id FROM travel_order_form WHERE id='{}'".format(id)
	g.cur.execute(sql)
	user_id = g.cur.fetchall()[0][0]

	sql = "SELECT contact, type FROM employee_info WHERE id='{}'".format(user_id)
	g.cur.execute(sql)
	contact = g.cur.fetchall()[0]

	if contact[1] == 'TEACHING':
		sql = "UPDATE travel_order_form SET head_human_resource_department='{}', status='VP' WHERE id='{}'".format(head_human_resource_department,id)
	else:
		sql = "UPDATE travel_order_form SET head_human_resource_department='{}', status='VP-ADMIN' WHERE id='{}'".format(head_human_resource_department,id)

	g.cur.execute(sql)
	g.conn.commit()
	
	_message = "Travel Order Approved by Human Resource Department. Forwarded to Vice President."
	send_sms(contact[0], _message)

	_message = "Pending Travel Order awaiting approval."
	sendGroupSMS(_message, 'VP')
	
	return jsonify({'data': 'success', 'route': 'view_hhrd_travel_order_forms'})

@app.route("/view_hhrd_leave_forms")
def view_hhrd_leave_forms():
	info = session['log']
	data = getLeaveForms(session['log'][5])
	return render_template("HHRD/display_leave_forms.html",data=data,info=info)

@app.route("/hhrd_view_leave_form/<int:id>")
def hhrd_view_leave_form(id):
	info = session['log']
	data = getLeaveFormData(id)
	return render_template("HHRD/view_leave_form.html",data=data,info=info)

@app.route("/hhrd_approve_leave_form/<int:id>",methods=['POST'])
def hhrd_approve_leave_form(id):
	head_human_resource_department = request.form['head_human_resource_department']

	sql = "UPDATE leave_form SET head_human_resource_department='{}', status='SP' WHERE id='{}'".format(head_human_resource_department,id)
	g.cur.execute(sql)
	g.conn.commit()

	sql = "SELECT user_id FROM leave_form WHERE id='{}'".format(id)
	g.cur.execute(sql)
	user_id = g.cur.fetchall()[0][0]

	sql = "SELECT contact FROM employee_info WHERE id='{}'".format(user_id)
	g.cur.execute(sql)
	contact = g.cur.fetchall()[0][0]

	_message = "Leave Approved by Human Resource. Forwarded to School President."
	send_sms(contact, _message)

	_message = "Pending Leave Form awaiting approval."
	sendGroupSMS(_message, 'SP')
	return jsonify({'data': 'success', 'route': 'view_hhrd_leave_forms'})

@app.route("/view_hhrd_overtime_authorization")
def view_hhrd_overtime_authorization():
	info = session['log']
	data = getOvertimeForms(session['log'][5])
	return render_template("HHRD/display_overtime_authorizations.html",data=data,info=info)

@app.route("/hhrd_view_overtime_authorization/<int:id>")
def hhrd_view_overtime_authorization(id):
	info = session['log']
	data = getOvertimeFormData(id)
	return render_template("HHRD/view_overtime_authorization.html",data=data,info=info)

@app.route("/hhrd_approve_overtime_authorization/<int:id>",methods=['POST'])
def hhrd_approve_overtime_authorization(id):
	head_human_resource_department = request.form['head_human_resource_department']
	approved_date = date.today()

	sql = "UPDATE overtime_authorization SET head_human_resource_department='{}', status='APPROVED', approved_date= '{}' WHERE id='{}'".format(head_human_resource_department, approved_date, id)
	g.cur.execute(sql)
	g.conn.commit()

	sql = "SELECT user_id FROM overtime_authorization WHERE id='{}'".format(id)
	g.cur.execute(sql)
	user_id = g.cur.fetchall()[0][0]

	sql = "SELECT contact FROM employee_info WHERE id='{}'".format(user_id)
	g.cur.execute(sql)
	contact = g.cur.fetchall()[0][0]

	_message = "Overtime Authorization Approved by Human Resource."
	send_sms(contact, _message)
	return jsonify({'data': 'success', 'route': 'view_hhrd_overtime_authorization'})

	# sendMessage("Your Overtime Authorization has been APPROVED",id,"overtime_authorization")
	# return redirect(url_for("view_hhrd_overtime_authorization"))

# ----------------------------------- END HHRD ------------------------------------------- #

# -------------------------------------- VP ---------------------------------------------- #

@app.route("/vp")
def vp():
	if "log" not in session:
		return redirect(url_for("login"))
	return redirect(url_for('index'))

@app.route("/view_vp_travel_order_forms")
def view_vp_travel_order_forms():
	info = session['log']
	data = getTravelForms(session['log'][5])
	return render_template("VP/display_travel_order_request.html",data=data,info=info)

@app.route("/vp_view_travel_order_form/<int:id>")
def vp_view_travel_order_form(id):
	info = session['log']
	data = getTravelFormData(id)
	return render_template("VP/view_travel_order_form.html",data=data,info=info)

@app.route("/vp_approve_travel_order_form/<int:id>",methods=['POST'])
def vp_approve_travel_order_form(id):
	vp = request.form['VP']

	sql = "UPDATE travel_order_form SET VP='{}', status='APPROVED' WHERE id='{}'".format(vp,id)
	g.cur.execute(sql)
	g.conn.commit()

	sql = "SELECT user_id, travel_date FROM travel_order_form WHERE id='{}'".format(id)
	g.cur.execute(sql)
	user_id = g.cur.fetchall()[0]

	sql = "SELECT contact FROM employee_info WHERE id='{}'".format(user_id[0])
	g.cur.execute(sql)
	contact = g.cur.fetchall()[0][0]

	_message = "Your Travel Order Form has been APPROVED Dated " + user_id[1]
	send_sms(contact, _message)

	return jsonify({'data': 'success', 'route': 'view_vp_travel_order_forms'})

	# sendMessage("Your Travel Order Form has been APPROVED",id,"travel_order_form")

# ------------------------------------- END VP --------------------------------------------- #

# -------------------------------------- VP - ADMIN ---------------------------------------------- #

@app.route("/view_vpadmin_travel_order_forms")
def view_vpadmin_travel_order_forms():
	info = session['log']
	data = getTravelForms(session['log'][5])
	return render_template("VP-ADMIN/display_travel_order_request.html",data=data,info=info)

@app.route("/vpadmin_view_travel_order_form/<int:id>")
def vpadmin_view_travel_order_form(id):
	info = session['log']
	data = getTravelFormData(id)
	return render_template("VP-ADMIN/view_travel_order_form.html",data=data,info=info)

@app.route("/vpadmin_approve_travel_order_form/<int:id>",methods=['POST'])
def vpadmin_approve_travel_order_form(id):
	vp = request.form['VP']

	sql = "UPDATE travel_order_form SET VP='{}', status='APPROVED' WHERE id='{}'".format(vp,id)
	g.cur.execute(sql)
	g.conn.commit()

	sql = "SELECT user_id, travel_date FROM travel_order_form WHERE id='{}'".format(id)
	g.cur.execute(sql)
	user_id = g.cur.fetchall()[0]

	sql = "SELECT contact FROM employee_info WHERE id='{}'".format(user_id[0])
	g.cur.execute(sql)
	contact = g.cur.fetchall()[0][0]

	_message = "Your Travel Order Form has been APPROVED Dated " + user_id[1]
	send_sms(contact, _message)

	return jsonify({'data': 'success', 'route': 'view_vpadmin_travel_order_forms'})

	# sendMessage("Your Travel Order Form has been APPROVED",id,"travel_order_form")

# ------------------------------------- END VP --------------------------------------------- #

# -------------------------------------- SP ---------------------------------------------- #

@app.route("/view_sp_leave_forms")
def view_sp_leave_forms():
	info = session['log']
	data = getLeaveForms(session['log'][5])
	return render_template("SP/display_leave_forms.html",data=data,info=info)

@app.route("/sp_view_leave_form/<int:id>")
def sp_view_leave_form(id):
	info = session['log']
	data = getLeaveFormData(id)
	return render_template("SP/view_leave_form.html",data=data,info=info)

@app.route("/sp_approve_leave_form/<int:id>",methods=['POST'])
def sp_approve_leave_form(id):
	school_president = request.form['school_president']

	sql = "UPDATE leave_form SET school_president='{}', status='APPROVED' WHERE id='{}'".format(school_president,id)
	g.cur.execute(sql)
	g.conn.commit()

	sql = "SELECT user_id, _from, _to FROM leave_form WHERE id='{}'".format(id)
	g.cur.execute(sql)
	user_id = g.cur.fetchall()[0]

	sql = "SELECT contact FROM employee_info WHERE id='{}'".format(user_id[0])
	g.cur.execute(sql)
	contact = g.cur.fetchall()[0][0]

	_message = "Your Travel Order Form has been APPROVED Dated " + user_id[1] + ' - ' + user_id[2]
	send_sms(contact, _message)

	return jsonify({'data': 'success', 'route': 'view_sp_leave_forms'})

# ------------------------------------- END SP --------------------------------------------- #

# ----------------------------------- ALL EMPLOYEE ------------------------------------------- #

@app.route("/outgoing")
def outgoing():
	if 'log' not in session:
		return redirect(url_for("login"))
	info = session['log']
	name = info[1] + ' ' + info[2]

	travel = getTravelOutgoingForms(info[5])
	leave = getLeaveOutgoingForms(info[5], name)
	overtime = getOvertimeOutgoingForms(info[5], name)

	if info[5] == 'DH':
		return render_template("dh/outgoing.html",info=info, travel=travel, leave=leave, overtime=overtime)
	elif info[5] == "PMO":
		return render_template("pmo/outgoing.html",info=info, travel=travel)
	elif info[5] == 'HHRD':
		return render_template("hhrd/outgoing.html",info=info, travel=travel, leave=leave, overtime=overtime)
	elif info[5] == 'VP':
		return render_template("vp/outgoing.html",info=info, travel=travel)
	elif info[5] == 'VP-ADMIN':
		return render_template("VP-ADMIN/outgoing.html",info=info, travel=travel)
	elif info[5] == 'SP':
		return render_template("sp/outgoing.html",info=info, leave=leave)
	
def getTravelOutgoingForms(account_type):
	sql = ""
	if account_type == 'DH':
		dept = session['log'][11]
		sql = "SELECT * FROM travel_order_form JOIN accounts ON travel_order_form.user_id = accounts.id WHERE department = '{}' and travel_order_form.status != 'DH'".format(dept)
	elif account_type == 'PMO':
		sql = "SELECT * FROM travel_order_form WHERE status != 'PMO'"
	elif account_type == 'HHRD':
		sql = "SELECT * FROM travel_order_form WHERE status != 'PMO' AND status != 'HHRD'"
	elif account_type == 'VP':
		sql = "SELECT * FROM travel_order_form WHERE status == 'APPROVED'"
	g.cur.execute(sql)
	return g.cur.fetchall()

def getLeaveOutgoingForms(account_type, name):
	sql = ""
	if account_type == 'DH':
		sql = "SELECT * FROM leave_form WHERE leave_form.department_head == '{}'".format(name)
	elif account_type == 'HHRD':
		sql = "SELECT * FROM leave_form WHERE leave_form.head_human_resource_department == '{}'".format(name)
	elif account_type == 'SP':
		sql = "SELECT * FROM leave_form WHERE status == 'APPROVED'"
	g.cur.execute(sql)
	return g.cur.fetchall()
	
def getOvertimeOutgoingForms(account_type, name):
	sql = ""
	if account_type == 'DH':
		sql = "SELECT * FROM overtime_authorization WHERE overtime_authorization.department_head = '{}'".format(name)
	elif account_type == 'HHRD':
		sql = "SELECT * FROM overtime_authorization WHERE overtime_authorization.head_human_resource_department = '{}'".format(name)
	# 	id = session['log'][0]
	# 	sql = "SELECT * FROM petty_cash WHERE user_id = '{}'".format(id)
	g.cur.execute(sql)
	return g.cur.fetchall()
	
@app.route("/employee")
def employee():
	if "log" not in session:
		return redirect(url_for("login"))
	info = session['log']
	year = date.today().year

	sql = "SELECT * FROM leave_days WHERE user_id = '{}' and year = '{}'".format(info[0],year)
	g.cur.execute(sql)
	remaining_leave = g.cur.fetchall()

	return render_template("employee/index.html",info=info,remaining_leave=remaining_leave)

@app.route("/view_leave_form/<int:id>")
def view_leave_form(id):
	info = session['log']
	data = getLeaveFormData(id)

	if session['log'][5] == "PMO":
		return render_template("PMO/own_leave_form.html",data=data,info=info)
	elif session['log'][5] == "DH":
		return render_template("DH/own_leave_form.html",data=data,info=info)
	elif session['log'][5] == "HHRD":
		return render_template("HHRD/own_leave_form.html",data=data,info=info)
	elif session['log'][5] == "VP":
		return render_template("VP/own_leave_form.html",data=data,info=info)
	elif session['log'][5] == "VP-ADMIN":
		return render_template("VP-ADMIN/own_leave_form.html",data=data,info=info)
	elif session['log'][5] == "SP":
		return render_template("SP/own_leave_form.html",data=data,info=info)
	else:
		return render_template("employee/view_leave_form.html",data=data,info=info)

@app.route("/view_travel_order_form/<int:id>")
def view_travel_order_form(id):
	info = session['log']
	data = getTravelFormData(id)
	if session['log'][5] == "PMO":
		return render_template("PMO/own_travel_order_form.html",data=data,info=info)
	elif session['log'][5] == "DH":
		return render_template("DH/own_travel_order_form.html",data=data,info=info)
	elif session['log'][5] == "HHRD":
		return render_template("HHRD/own_travel_order_form.html",data=data,info=info)
	elif session['log'][5] == "VP":
		return render_template("VP/own_travel_order_form.html",data=data,info=info)
	elif session['log'][5] == "VP-ADMIN":
		return render_template("VP-ADMIN/own_travel_order_form.html",data=data,info=info)
	elif session['log'][5] == "SP":
		return render_template("SP/own_travel_order_form.html",data=data,info=info)
	else:
		return render_template("employee/view_travel_order_form.html",data=data,info=info)

@app.route("/view_overtime_authorization/<int:id>")
def view_overtime_authorization(id):
	info = session['log']
	data = getOvertimeFormData(id)
	
	if session['log'][5] == "PMO":
		return render_template("PMO/own_overtime_authorization.html",data=data,info=info)
	elif session['log'][5] == "DH":
		return render_template("DH/own_overtime_authorization.html",data=data,info=info)
	elif session['log'][5] == "HHRD":
		return render_template("HHRD/own_overtime_authorization.html",data=data,info=info)
	elif session['log'][5] == "VP":
		return render_template("VP/own_overtime_authorization.html",data=data,info=info)
	elif session['log'][5] == "VP-ADMIN":
		return render_template("VP-ADMIN/own_overtime_authorization.html",data=data,info=info)
	elif session['log'][5] == "SP":
		return render_template("SP/own_overtime_authorization.html",data=data,info=info)
	else:
	
		return render_template("employee/view_overtime_authorization.html",data=data,info=info)

@app.route("/my_forms")
def my_forms():
	if "log" not in session:
		return redirect(url_for("login"))	
	info = session['log']
	
	travel = getMyForms(session['log'][0], 'Travel Form')
	leave = getMyForms(session['log'][0], 'Leave Form')
	overtime = getMyForms(session['log'][0], 'Overtime Form')
	
	if session['log'][5] == "PMO":
		return render_template("PMO/my_forms.html",info=info, leave=leave, overtime=overtime, travel=travel)
	elif session['log'][5] == "DH":
		return render_template("DH/my_forms.html",info=info, leave=leave, overtime=overtime, travel=travel)
	elif session['log'][5] == "HHRD":
		return render_template("HHRD/my_forms.html",info=info, leave=leave, overtime=overtime, travel=travel)
	elif session['log'][5] == "VP":
		return render_template("VP/my_forms.html",info=info, leave=leave, overtime=overtime, travel=travel)
	elif session['log'][5] == "VP-ADMIN":
		return render_template("VP-ADMIN/my_forms.html",info=info, leave=leave, overtime=overtime, travel=travel)
	elif session['log'][5] == "SP":
		return render_template("SP/my_forms.html",info=info, leave=leave, overtime=overtime, travel=travel)
	elif session['log'][5] == "EMPLOYEE":
		return render_template("employee/my_forms.html",info=info, leave=leave, overtime=overtime, travel=travel)
	else:
		travel = getTravelForms('ADMIN')
		leave = getLeaveForms('ADMIN')
		overtime = getOvertimeForms('ADMIN')
		return render_template("forms.html",info=info, leave=leave, overtime=overtime, travel=travel)

@app.route("/travel_order_form")
def travel_order_form():
	if "log" not in session:
		return redirect(url_for("login"))
	info = session['log']
	
	sql = "SELECT * FROM department WHERE status='Active'"
	g.cur.execute(sql)
	department = g.cur.fetchall()

	if session['log'][5] == "PMO":
		return render_template("PMO/travel_order_form.html",info=info, department=department)
	elif session['log'][5] == "DH":
		return render_template("DH/travel_order_form.html",info=info, department=department)
	elif session['log'][5] == "HHRD":
		return render_template("HHRD/travel_order_form.html",info=info, department=department)
	elif session['log'][5] == "VP":
		return render_template("VP/travel_order_form.html",info=info, department=department)
	elif session['log'][5] == "VP-ADMIN":
		return render_template("VP-ADMIN/travel_order_form.html",info=info, department=department)
	elif session['log'][5] == "SP":
		return render_template("SP/travel_order_form.html",info=info, department=department)
	else:
		return render_template("employee/travel_order_form.html",info=info, department=department)

@app.route("/leave_form")
def leave_form():
	if "log" not in session:
		return redirect(url_for("login"))
	info = session['log']

	year = date.today().year
	sql = "SELECT * FROM leave_days WHERE user_id = '{}' and year = '{}'".format(info[0],year)
	g.cur.execute(sql)
	remaining_leave = g.cur.fetchall()
	
	if session['log'][5] == "PMO":
		return render_template("PMO/leave_form.html",info=info,remaining_leave=remaining_leave)
	elif session['log'][5] == "DH":
		return render_template("DH/leave_form.html",info=info,remaining_leave=remaining_leave)
	elif session['log'][5] == "HHRD":
		return render_template("HHRD/leave_form.html",info=info,remaining_leave=remaining_leave)
	elif session['log'][5] == "VP":
		return render_template("VP/leave_form.html",info=info,remaining_leave=remaining_leave)
	elif session['log'][5] == "VP-ADMIN":
		return render_template("VP-ADMIN/leave_form.html",info=info,remaining_leave=remaining_leave)
	elif session['log'][5] == "SP":
		return render_template("SP/leave_form.html",info=info,remaining_leave=remaining_leave)
	else:
		return render_template("employee/leave_form.html",info=info,remaining_leave=remaining_leave)

@app.route("/overtime_authorization")
def overtime_authorization():
	if "log" not in session:
		return redirect(url_for("login"))
	info = session['log']

	if session['log'][5] == "PMO":
		return render_template("PMO/overtime_authorization.html",info=info)
	elif session['log'][5] == "DH":
		return render_template("DH/overtime_authorization.html",info=info)
	elif session['log'][5] == "HHRD":
		return render_template("HHRD/overtime_authorization.html",info=info)
	elif session['log'][5] == "VP":
		return render_template("VP/overtime_authorization.html",info=info)
	elif session['log'][5] == "VP-ADMIN":
		return render_template("VP-ADMIN/overtime_authorization.html",info=info)
	elif session['log'][5] == "SP":
		return render_template("SP/overtime_authorization.html",info=info)
	else:
		return render_template("employee/overtime_authorization.html",info=info)

@app.route("/submit_leave_form/<int:id>",methods=['POST'])
def submit_leave_form(id):
	fullname = request.form['fullname']
	designation = request.form['designation']
	date_filed = request.form['date_filed']
	reasons = request.form['reasons']
	_from = request.form['from']
	_to = request.form['to']
	nature_of_leave = request.form['nature_of_leave']
	others = request.form['others']
	number_of_days = request.form['number_of_days']
	return_date = request.form['return_date']
	employee_name_signature = request.form['employee_name_signature']

	sql = "INSERT INTO leave_form(user_id,fullname,designation,date_filed,reasons,_from,_to,nature_of_leave,others,number_of_days,return_date,employee_name_signature) VALUES('{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}')".format(id,fullname,designation,date_filed,reasons,_from,_to,nature_of_leave,others,number_of_days,return_date,employee_name_signature)
	g.cur.execute(sql)
	g.conn.commit()

	if nature_of_leave == '(SIL) Service Incentive Leave':
		param = "service_leave"
	elif nature_of_leave == '(ML) Maternity Leave':
		param = "maternity_leave"
	elif nature_of_leave == '(PL) Paternity Leave':
		param = "paternity_leave"
	elif nature_of_leave == '(PLSP) Parental Leave for Solo Parent':
		param = "parental_leave"
	elif nature_of_leave == 'Sick Leave':
		param = "sick_leave"
	
	sql = "UPDATE leave_days SET {} = {} - {} WHERE user_id = '{}'".format(param, param, number_of_days, id)
	g.cur.execute(sql)
	g.conn.commit()

	contact = session['log'][9]
	_message = "Leave Application Submitted. Forwarded to Department Head."
	send_sms(contact, _message)

	_message = "Pending Leave Application awaiting approval."
	sendGroupSMS(_message, 'DH')

	return jsonify({'data': 'success', 'route': 'my_forms'})

@app.route("/submit_travel_order_form/<int:id>",methods=['POST'])
def submit_travel_order_form(id):
	fullname = request.form['fullname']
	department = request.form['department']
	date_filed = request.form['date_filed']
	travel_date = request.form['travel_date']
	travel_time_duration = request.form['travel_time_duration']
	reasons = request.form['reasons']
	destination = request.form['destination']
	specify = request.form['specify']
	employee_name_signature = request.form['employee_name_signature']

	sql = "INSERT INTO travel_order_form(user_id,fullname,department,date_filed,travel_date,travel_time_duration,reasons,destination,specify,employee_name_signature) VALUES('{}','{}','{}','{}','{}','{}','{}','{}','{}','{}')".format(id,fullname,department,date_filed,travel_date,travel_time_duration,reasons,destination,specify,employee_name_signature)
	g.cur.execute(sql)
	g.conn.commit()

	contact = session['log'][9]
	_message = "Travel Order Submitted. Forwarded to Department Head."
	send_sms(contact, _message)

	_message = "Pending Travel Order awaiting approval."
	sendGroupSMS(_message, 'DH')

	return jsonify({'data': 'success', 'route': 'my_forms'})

@app.route("/submit_overtime_authorization/<int:id>",methods=['POST'])
def submit_overtime_authorization(id):
	fullname = request.form['fullname']
	designation = request.form['designation']
	date_filed = request.form['date_filed']
	overtime = request.form['overtime']
	specify = request.form['specify']
	reason = request.form['reason']
	official_time_in = request.form['official_time_in']
	official_time_out = request.form['official_time_out']
	overtime_time_out = request.form['overtime_time_out']
	total_hours = request.form['total_hours']
	employee_name_signature = request.form['employee_name_signature']

	sql = "INSERT INTO overtime_authorization(user_id,fullname,designation,date_filed,overtime,specify,reasons,official_time_in,official_time_out,overtime_time_out,total_hours,employee_name_signature) VALUES('{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}')".format(id,fullname,designation,date_filed,overtime,specify,reason,official_time_in,official_time_out,overtime_time_out,total_hours,employee_name_signature)
	g.cur.execute(sql)
	g.conn.commit()

	contact = session['log'][9]
	_message = "Overtime Request Submitted. Forwarded to Department Head."
	send_sms(contact, _message)

	_message = "Pending Overtime Request awaiting approval."
	sendGroupSMS(_message, 'DH')

	return jsonify({'data': 'success', 'route': 'my_forms'})

@app.route("/profile")
def profile():
	if "log" not in session:
		return redirect(url_for("login"))
	info = session['log']

	sql = "SELECT * FROM accounts JOIN employee_info ON accounts.id = employee_info.id WHERE accounts.id = '{}'".format(info[0])
	g.cur.execute(sql)
	user = g.cur.fetchall()
	
	if session['log'][5] == "PMO":
		return render_template("PMO/profile.html",info=info,user=user)
	elif session['log'][5] == "DH":
		return render_template("DH/profile.html",info=info,user=user)
	elif session['log'][5] == "HHRD":
		return render_template("HHRD/profile.html",info=info,user=user)
	elif session['log'][5] == "VP":
		return render_template("VP/profile.html",info=info,user=user)
	elif session['log'][5] == "SP":
		return render_template("SP/profile.html",info=info,user=user)
	else:
		return render_template("employee/profile.html",info=info,user=user)

@app.route('/edit_profile',methods=['POST'])
def edit_profile():
	_id = session['log'][0]
	fname = request.form['fname'].title()
	lname = request.form['lname'].title()
	email = request.form['email']
	contact = request.form['contact']
	address = request.form['address'].title()
	designation = request.form['designation']

	sql = "UPDATE accounts SET fname = '{}', lname = '{}' WHERE id = '{}'".format(fname, lname, _id)
	g.cur.execute(sql)
	g.conn.commit()

	sql = "UPDATE employee_info SET email = '{}', contact = '{}', address = '{}', designation = '{}' WHERE id = '{}'".format(email, contact, address, designation, _id)
	g.cur.execute(sql)
	g.conn.commit()

	return redirect(url_for("profile"))

def getDH(user_dept):
	sql = "SELECT * FROM accounts JOIN employee_info ON accounts.id = employee_info.id WHERE dept_id = '{}' and account_type = 'DH' and status = 'Active'".format(user_dept)
	g.cur.execute(sql)
	return g.cur.fetchone()

def getSignatory(account_type):
	sql = "SELECT * FROM accounts JOIN employee_info ON accounts.id = employee_info.id WHERE account_type = '{}' and status = 'Active'".format(account_type)
	g.cur.execute(sql)
	return g.cur.fetchall()[0]
# ----------------------------------- END ALL EMPLOYEE ------------------------------------------- #

@app.route("/login")
def login():
	if "log" in session:
		return redirect(url_for("routing"))
	return render_template("login.html")

@app.before_first_request
def auto_add_leave():
	conn()
	year = date.today().year
	
	sql = "SELECT id FROM employee_info"
	g.cur.execute(sql)
	employee_ids = g.cur.fetchall()

	for id in employee_ids:
		sql = "SELECT * FROM leave_days WHERE user_id = '{}' and year = '{}'".format(id[0], year)
		g.cur.execute(sql)
		result = g.cur.fetchall()

		if(len(result) == 0):
			sql = "INSERT INTO leave_days(user_id,service_leave,maternity_leave,paternity_leave,parental_leave,'sick_leave','year') VALUES('{}','5','105','7','7','15','{}')".format(id[0],year)
			g.cur.execute(sql)
			g.conn.commit()

	print("Done adding leave days")	

# ------------------------------------ ADMIN SIDE ------------------------------------------ #

@app.route("/report")
def report():
	if 'log' not in session:
		return redirect(url_for("routing"))
	data = session['log']

	sql = ''' SELECT * FROM travel_order_form
				JOIN employee_info ON travel_order_form.user_id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id '''
	g.cur.execute(sql)
	travel = g.cur.fetchall()
	
	sql = ''' SELECT * FROM leave_form
				JOIN employee_info ON leave_form.user_id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id '''
	g.cur.execute(sql)
	leave = g.cur.fetchall()

	sql = ''' SELECT * FROM overtime_authorization
				JOIN employee_info ON overtime_authorization.user_id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id '''
	g.cur.execute(sql)
	overtime = g.cur.fetchall()

	sql = ''' SELECT * FROM department WHERE status = 'Active' '''
	g.cur.execute(sql)
	department = g.cur.fetchall()

	filter_type = date.today().year
	
	return render_template("report.html",data=data,travel=travel,leave=leave, overtime=overtime, department=department, filter_type=filter_type)

@app.route("/filter_report",methods=['POST'])
def filter_report():
	if 'log' not in session:
		return redirect(url_for("routing"))
	filter_type = ""
	data = session['log']
	year = request.form['year']
	if "month" in request.form and "department" in request.form:
		month = request.form['month']
		department = request.form['department']
		sql = ''' SELECT * FROM travel_order_form
				JOIN employee_info ON travel_order_form.user_id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',travel_order_form.date_filed) = '{}' and strftime('%m',travel_order_form.date_filed) = '{}' and department.department = '{}' '''.format(year,month,department)
		g.cur.execute(sql)
		travel = g.cur.fetchall()

		sql = ''' SELECT * FROM leave_form
				JOIN employee_info ON leave_form.user_id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',leave_form.date_filed) = '{}' and strftime('%m',leave_form.date_filed) = '{}' and department.department = '{}' '''.format(year,month,department)
		g.cur.execute(sql)
		leave = g.cur.fetchall()

		sql = ''' SELECT * FROM overtime_authorization
				JOIN employee_info ON overtime_authorization.user_id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',overtime_authorization.date_filed) = '{}' and strftime('%m',overtime_authorization.date_filed) = '{}' and department.department = '{}' '''.format(year,month,department)
		g.cur.execute(sql)
		overtime = g.cur.fetchall()

		if month == '01': month = 'January'
		if month == '02': month = 'February'
		if month == '03': month = 'March'
		if month == '04': month = 'April'
		if month == '05': month = 'May'
		if month == '06': month = 'June'
		if month == '07': month = 'July'
		if month == '08': month = 'August'
		if month == '09': month = 'September'
		if month == '10': month = 'October'
		if month == '11': month = 'November'
		if month == '12': month = 'December'
		filter_type = month + ' ' + year + ' ' + department

	elif "month" in request.form:
		month = request.form['month']
		sql = ''' SELECT * FROM travel_order_form
				JOIN employee_info ON travel_order_form.user_id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',travel_order_form.date_filed) = '{}' and strftime('%m',travel_order_form.date_filed) = '{}' '''.format(year,month)
		g.cur.execute(sql)
		travel = g.cur.fetchall()

		sql = ''' SELECT * FROM leave_form
				JOIN employee_info ON leave_form.user_id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',leave_form.date_filed) = '{}' and strftime('%m',leave_form.date_filed) = '{}' '''.format(year,month)
		g.cur.execute(sql)
		leave = g.cur.fetchall()

		sql = ''' SELECT * FROM overtime_authorization
				JOIN employee_info ON overtime_authorization.user_id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',overtime_authorization.date_filed) = '{}' and strftime('%m',overtime_authorization.date_filed) = '{}' '''.format(year,month)
		g.cur.execute(sql)
		overtime = g.cur.fetchall()

		if month == '01': month = 'January'
		if month == '02': month = 'February'
		if month == '03': month = 'March'
		if month == '04': month = 'April'
		if month == '05': month = 'May'
		if month == '06': month = 'June'
		if month == '07': month = 'July'
		if month == '08': month = 'August'
		if month == '09': month = 'September'
		if month == '10': month = 'October'
		if month == '11': month = 'November'
		if month == '12': month = 'December'
		filter_type = month + ' ' + year

	elif "department" in request.form:
		department = request.form['department']
		sql = ''' SELECT * FROM travel_order_form
				JOIN employee_info ON travel_order_form.user_id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',travel_order_form.date_filed) = '{}' and department.department = '{}' '''.format(year,department)
		g.cur.execute(sql)
		travel = g.cur.fetchall()

		sql = ''' SELECT * FROM leave_form
				JOIN employee_info ON leave_form.user_id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',leave_form.date_filed) = '{}' and department.department = '{}' '''.format(year,department)
		g.cur.execute(sql)
		leave = g.cur.fetchall()

		sql = ''' SELECT * FROM overtime_authorization
				JOIN employee_info ON overtime_authorization.user_id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',overtime_authorization.date_filed) = '{}' and department.department = '{}' '''.format(year,department)
		g.cur.execute(sql)
		overtime = g.cur.fetchall()
		filter_type = year + ' ' + department

	else:
		sql = ''' SELECT * FROM travel_order_form
				JOIN employee_info ON travel_order_form.user_id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',travel_order_form.date_filed) = '{}' '''.format(year)
		g.cur.execute(sql)
		travel = g.cur.fetchall()

		sql = ''' SELECT * FROM leave_form
				JOIN employee_info ON leave_form.user_id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',leave_form.date_filed) = '{}' '''.format(year)
		g.cur.execute(sql)
		leave = g.cur.fetchall()

		sql = ''' SELECT * FROM overtime_authorization
				JOIN employee_info ON overtime_authorization.user_id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',overtime_authorization.date_filed) = '{}' '''.format(year)
		g.cur.execute(sql)
		overtime = g.cur.fetchall()
		filter_type = year

	sql = ''' SELECT * FROM department WHERE status = 'Active' '''
	g.cur.execute(sql)
	department = g.cur.fetchall()
	
	return render_template("report.html",data=data, travel=travel, leave=leave, overtime=overtime, filter_type=filter_type, department=department)

@app.route("/report_remaining_leave")
def report_remaining_leave():
	if 'log' not in session:
		return redirect(url_for("routing"))
	data = session['log']
	year = date.today().year

	sql = ''' SELECT fname, lname, department, service_leave, maternity_leave, paternity_leave, parental_leave, sick_leave FROM leave_days
				JOIN employee_info ON employee_info.id = leave_days.user_id
				JOIN accounts ON accounts.id = employee_info.id
				JOIN department ON department.id = employee_info.dept_id
				WHERE year = '{}' '''.format(year)
	g.cur.execute(sql)
	remaining_leave = g.cur.fetchall()
	
	sql = ''' SELECT * FROM department WHERE status = 'Active' '''
	g.cur.execute(sql)
	department = g.cur.fetchall()

	filter_type = "Overall"

	return render_template("report_remaining_leave.html",data=data, remaining_leave=remaining_leave, department=department, filter_type=filter_type)

@app.route("/filter_report_remaining_leave",methods=['POST'])
def filter_report_remaining_leave():
	if 'log' not in session:
		return redirect(url_for("routing"))
	filter_type = ""
	data = session['log']
	year = request.form['year']

	if "department" in request.form:
		department = request.form['department']
		sql = ''' SELECT fname, lname, department, service_leave, maternity_leave, paternity_leave, parental_leave, sick_leave FROM leave_days
					JOIN employee_info ON employee_info.id = leave_days.user_id
					JOIN accounts ON accounts.id = employee_info.id
					JOIN department ON department.id = employee_info.dept_id
					WHERE year = '{}' AND department.department = '{}' '''.format(year,department)
		g.cur.execute(sql)
		remaining_leave = g.cur.fetchall()

		filter_type = year + ' ' + department

	else:
		sql = ''' SELECT fname, lname, department, service_leave, maternity_leave, paternity_leave, parental_leave, sick_leave FROM leave_days
					JOIN employee_info ON employee_info.id = leave_days.user_id
					JOIN accounts ON accounts.id = employee_info.id
					JOIN department ON department.id = employee_info.dept_id
					WHERE year = '{}' '''.format(year)
		g.cur.execute(sql)
		remaining_leave = g.cur.fetchall()

		filter_type = year

	sql = ''' SELECT * FROM department WHERE status = 'Active' '''
	g.cur.execute(sql)
	department = g.cur.fetchall()
	
	return render_template("report_remaining_leave.html",data=data, remaining_leave=remaining_leave, department=department, filter_type=filter_type)

@app.route("/report_travel")
def report_travel():
	if 'log' not in session:
		return redirect(url_for("routing"))
	data = session['log']

	sql = ''' SELECT fullname, department.department, count(travel_order_form.id) as total FROM travel_order_form
				JOIN employee_info ON employee_info.id = travel_order_form.user_id
				JOIN department ON department.id = employee_info.dept_id
				GROUP BY travel_order_form.user_id '''
	g.cur.execute(sql)
	travel = g.cur.fetchall()

	sql = ''' SELECT * FROM department WHERE status = 'Active' '''
	g.cur.execute(sql)
	department = g.cur.fetchall()

	filter_type = date.today().year
	return render_template("report_travel.html",data=data, travel=travel, department=department, filter_type=filter_type)

@app.route("/filter_report_travel",methods=['POST'])
def filter_report_travel():
	if 'log' not in session:
		return redirect(url_for("routing"))
	filter_type = ""
	data = session['log']
	year = request.form['year']
	
	if "month" in request.form and "department" in request.form:
		month = request.form['month']
		department = request.form['department']
		
		sql = ''' SELECT fullname, department.department, count(travel_order_form.id) as total FROM travel_order_form
				JOIN employee_info ON employee_info.id = travel_order_form.user_id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',travel_order_form.date_filed) = '{}' and strftime('%m',travel_order_form.date_filed) = '{}' and department.department = '{}'
				GROUP BY travel_order_form.user_id '''.format(year,month,department)
		g.cur.execute(sql)
		travel = g.cur.fetchall()

		if month == '01': month = 'January'
		if month == '02': month = 'February'
		if month == '03': month = 'March'
		if month == '04': month = 'April'
		if month == '05': month = 'May'
		if month == '06': month = 'June'
		if month == '07': month = 'July'
		if month == '08': month = 'August'
		if month == '09': month = 'September'
		if month == '10': month = 'October'
		if month == '11': month = 'November'
		if month == '12': month = 'December'
		filter_type = month + ' ' + year + ' ' + department

	elif "month" in request.form:
		month = request.form['month']
		sql = ''' SELECT fullname, department.department, count(travel_order_form.id) as total FROM travel_order_form
				JOIN employee_info ON employee_info.id = travel_order_form.user_id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',travel_order_form.date_filed) = '{}' and strftime('%m',travel_order_form.date_filed) = '{}'
				GROUP BY travel_order_form.user_id '''.format(year,month)
		
		g.cur.execute(sql)
		travel = g.cur.fetchall()

		if month == '01': month = 'January'
		if month == '02': month = 'February'
		if month == '03': month = 'March'
		if month == '04': month = 'April'
		if month == '05': month = 'May'
		if month == '06': month = 'June'
		if month == '07': month = 'July'
		if month == '08': month = 'August'
		if month == '09': month = 'September'
		if month == '10': month = 'October'
		if month == '11': month = 'November'
		if month == '12': month = 'December'
		filter_type = month + ' ' + year

	elif "department" in request.form:
		department = request.form['department']
		sql = ''' SELECT fullname, department.department, count(travel_order_form.id) as total FROM travel_order_form
				JOIN employee_info ON employee_info.id = travel_order_form.user_id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',travel_order_form.date_filed) = '{}' and department.department = '{}' 
				GROUP BY travel_order_form.user_id '''.format(year,department)
		g.cur.execute(sql)
		travel = g.cur.fetchall()
		
		filter_type = year + ' ' + department

	else:
		sql = ''' SELECT fullname, department.department, count(travel_order_form.id) as total FROM travel_order_form
				JOIN employee_info ON employee_info.id = travel_order_form.user_id
				JOIN department ON department.id = employee_info.dept_id
				WHERE strftime('%Y',travel_order_form.date_filed) = '{}'
				GROUP BY travel_order_form.user_id '''.format(year)
		g.cur.execute(sql)
		travel = g.cur.fetchall()

		filter_type = year

	sql = ''' SELECT * FROM department WHERE status = 'Active' '''
	g.cur.execute(sql)
	department = g.cur.fetchall()
	
	return render_template("report_travel.html",data=data, travel=travel, department=department, filter_type=filter_type)

@app.route("/view_department")
def view_department():
	if "log" not in session:
		return redirect(url_for("routing"))

	sql = "SELECT * FROM department"
	g.cur.execute(sql)
	data = g.cur.fetchall()
	return render_template("view_department.html",data=data)

@app.route('/add_department',methods=['POST'])
def add_department():
	department = request.form['department'].title()

	sql = "INSERT INTO department(department, status) VALUES('{}','Active')".format(department)
	g.cur.execute(sql)
	g.conn.commit()

	return redirect(url_for("view_department"))

@app.route('/edit_department',methods=['POST'])
def edit_department():
	_id = request.form['id']
	department = request.form['department'].title()
	status = request.form['status']

	sql = "UPDATE department SET department = '{}', status = '{}' WHERE id = '{}'".format(department, status, _id)
	g.cur.execute(sql)
	g.conn.commit()

	return redirect(url_for("view_department"))

@app.route("/view_office")
def view_office():
	if "log" not in session:
		return redirect(url_for("routing"))

	sql = "SELECT * FROM office"
	g.cur.execute(sql)
	data = g.cur.fetchall()
	return render_template("view_office.html",data=data)

@app.route('/add_office',methods=['POST'])
def add_office():
	office = request.form['office'].title()

	sql = "INSERT INTO office(office, status) VALUES('{}','Active')".format(office)
	g.cur.execute(sql)
	g.conn.commit()

	return redirect(url_for("view_office"))

@app.route('/edit_office',methods=['POST'])
def edit_office():
	_id = request.form['id']
	office = request.form['office'].title()
	status = request.form['status']

	sql = "UPDATE office SET office = '{}', status = '{}' WHERE id = '{}'".format(office, status, _id)
	g.cur.execute(sql)
	g.conn.commit()

	return redirect(url_for("view_office"))

@app.route("/view_employees")
def view_employees():
	if "log" not in session:
		return redirect(url_for("routing"))

	sql = '''SELECT * FROM accounts 
				INNER JOIN employee_info ON accounts.id=employee_info.id
				INNER JOIN department ON department.id=employee_info.dept_id
				INNER JOIN office ON office.id=employee_info.office_id'''
	g.cur.execute(sql)
	data = g.cur.fetchall()
	
	sql = "SELECT * FROM department WHERE status = 'Active'"
	g.cur.execute(sql)
	department = g.cur.fetchall()
	
	sql = "SELECT * FROM office WHERE status = 'Active'"
	g.cur.execute(sql)
	office = g.cur.fetchall()

	return render_template("view_employees.html",data=data, department=department, office=office)

@app.route('/add_employee',methods=['POST'])
def add_employee():
	fname = request.form['fname'].title()
	lname = request.form['lname'].title()
	email = request.form['email']
	contact = request.form['contact']
	address = request.form['address'].title()
	account_type = request.form['account_type']
	type = request.form['type']
	department = request.form['department']
	office = request.form['office']
	designation = request.form['designation']

	username = (("{}.{}".format(fname,lname)).lower()).replace(" ","")
	password = (("{}.{}".format(contact,email)).lower()).replace(" ","")
	sql = "INSERT INTO accounts(fname,lname,username,password,account_type,status) VALUES('{}','{}','{}','{}','{}','Active')".format(fname,lname,username,password,account_type)
	g.cur.execute(sql)
	g.conn.commit()
	_id = g.cur.lastrowid

	sql = "INSERT INTO employee_info(id,email,contact,address,dept_id,office_id,designation, type) VALUES('{}','{}','{}','{}','{}','{}','{}','{}')".format(_id,email,contact,address,department,office,designation,type)
	g.cur.execute(sql)
	g.conn.commit()

	sql = "INSERT INTO leave_days(user_id,service_leave,maternity_leave,paternity_leave,parental_leave,'sick_leave') VALUES('{}','5','105','7','7','15')".format(_id)
	g.cur.execute(sql)
	g.conn.commit()

	return redirect(url_for("view_employees"))

@app.route('/edit_employee',methods=['POST'])
def edit_employee():
	_id = request.form['id']
	department = request.form['department']
	office = request.form['office']
	type = request.form['type']
	designation = request.form['designation']
	status = request.form['status']

	sql = "UPDATE accounts SET status ='{}' WHERE id = {}".format(status, _id)
	g.cur.execute(sql)
	g.conn.commit()
	
	sql = "UPDATE employee_info SET dept_id ='{}', office_id = '{}', designation = '{}', type = '{}' WHERE id = {}".format(department, office, designation, type, _id)
	g.cur.execute(sql)
	g.conn.commit()

	return redirect(url_for("view_employees"))

# ------------------------------------ END ADMIN SIDE ------------------------------------------ #

@app.route("/change_password", methods=['POST'])
def change_password():
	_id = session['log'][0]
	old_password = request.form['old_password']
	new_password = request.form['new_password']

	sql = "SELECT * FROM accounts WHERE password='{}'".format(old_password)
	g.cur.execute(sql)
	data = g.cur.fetchall()
	
	info = session['log']

	if len(data) == 1:
		print('hi')
		sql = "UPDATE accounts SET password='{}' WHERE id='{}'".format(new_password,_id)
		g.cur.execute(sql)
		g.conn.commit()
		return redirect(url_for("routing"))
	else:
		if session['log'][5] == "ADMIN":
			return render_template("404.html")
		elif session['log'][5] == "DH":
			return render_template("DH/404.html", info=info)
		elif session['log'][5] == "PMO":
			return render_template("PMO/404.html", info=info)
		elif session['log'][5] == "HHRD":
			return render_template("HHRD/404.html", info=info)
		elif session['log'][5] == "VP":
			return render_template("VP/404.html", info=info)
		elif session['log'][5] == "SP":
			return render_template("SP/404.html", info=info)
		elif session['log'][5] == "EMPLOYEE":
			return render_template("employee/404.html", info=info)

@app.route("/login_process",methods=['POST'])
def login_process():
	username = request.form['username']
	password = request.form['password']

	sql = "SELECT * FROM accounts LEFT JOIN employee_info ON accounts.id = employee_info.id WHERE username='{}' AND password='{}' and status = 'Active'".format(username,password)
	g.cur.execute(sql)
	data = g.cur.fetchall()

	if(len(data) > 0):
		session['log'] = data[0]
	
	return redirect(url_for("routing"))

@app.route("/logout")
def logout():
	session.pop("log",None)
	return redirect(url_for("routing"))

@app.route("/routing")
def routing():
	if 'log' in session:
		if session['log'][5] == "EMPLOYEE":
			return redirect(url_for("employee"))
		elif session['log'][5] == "PMO":
			return redirect(url_for("pmo"))
		else:
			return redirect(url_for("index"))
	return redirect(url_for("login"))

@app.route("/dissaprove/<int:form_id>/<fname>/<lname>/<return_to>/<_form>/<reason>")
def dissaprove(form_id,fname,lname,return_to,_form,reason):
	message = (("Sorry your {} has been Dissaproved".format(_form)).replace("_"," ")).title()
	sql = "UPDATE {} SET status='DISAPPROVED', reason = '{}' WHERE id='{}'".format(_form,reason,form_id)
	g.cur.execute(sql)
	g.conn.commit()
	sendMessage(message,form_id,_form)
	return jsonify({'data': 'success', 'route': return_to})
	# return redirect(url_for(return_to))
	
def sendMessage(_message,form_id,db):
	print("{}\n{}\n{}".format(_message,form_id,db))

	sql = "SELECT user_id FROM {} WHERE id='{}'".format(db,form_id)
	g.cur.execute(sql)
	user_id = g.cur.fetchall()[0][0]

	sql = "SELECT contact FROM employee_info WHERE id='{}'".format(user_id)
	g.cur.execute(sql)
	contact = g.cur.fetchall()[0][0]
	send_sms(contact, _message)

	# contact = "+63{}".format(contact[1::])
	# message = client.messages.create(
	# 	body=_message,
	# 	from_="+13862725541",
	# 	to=contact
	# )

# -------------------------------------- Reusable Functions ------------------------------------------ #

def sendGroupSMS(message,account):
	if account == 'DH':
		department = session['log'][11]
		sql = "SELECT contact FROM accounts LEFT JOIN employee_info ON accounts.id = employee_info.id WHERE account_type = 'DH' and dept_id = '{}'".format(department)
	else:
		sql = "SELECT contact FROM accounts JOIN employee_info ON employee_info.id = accounts.id WHERE account_type='{}'".format(account)
		
	g.cur.execute(sql)
	contacts = [i[0] for i in g.cur.fetchall()]
	
	for contact in contacts:
		send_sms(contact, message)
	
	print("success")

def getTravelForms(account_type):
	if account_type == 'ADMIN':
		sql = "SELECT * FROM travel_order_form"
	elif account_type == 'DH':
		dept = session['log'][11]
		sql = "SELECT * FROM travel_order_form JOIN employee_info ON travel_order_form.user_id = employee_info.id WHERE dept_id = '{}' and status = 'DH'".format(dept)
	elif account_type == 'PMO':
		sql = "SELECT * FROM travel_order_form WHERE status = 'PMO'"
	elif account_type == 'HHRD':
		sql = "SELECT * FROM travel_order_form WHERE status = 'HHRD'"
	elif account_type == 'VP':
		sql = "SELECT * FROM travel_order_form WHERE status = 'VP'"
	elif account_type == 'VP-ADMIN':
		sql = "SELECT * FROM travel_order_form WHERE status = 'VP-ADMIN'"

	g.cur.execute(sql)
	return g.cur.fetchall()

def getLeaveForms(account_type):
	if account_type == 'ADMIN':
		sql = "SELECT * FROM leave_form"
	elif account_type == 'DH':
		dept = session['log'][11]
		sql = "SELECT * FROM leave_form JOIN employee_info ON leave_form.user_id = employee_info.id WHERE dept_id = '{}' and status = 'DH'".format(dept)
	elif account_type == 'PMO':
		sql = "SELECT * FROM leave_form WHERE status = 'PMO'"
	elif account_type == 'HHRD':
		sql = "SELECT * FROM leave_form WHERE status = 'HHRD'"
	elif account_type == 'VP':
		sql = "SELECT * FROM leave_form WHERE status = 'VP'"
	elif account_type == 'SP':
		sql = "SELECT * FROM leave_form WHERE status = 'SP'"

	g.cur.execute(sql)
	return g.cur.fetchall()

def getOvertimeForms(account_type):
	if account_type == 'ADMIN':
		sql = "SELECT * FROM overtime_authorization"
	elif account_type == 'DH':
		dept = session['log'][11]
		sql = "SELECT * FROM overtime_authorization JOIN employee_info ON overtime_authorization.user_id = employee_info.id WHERE dept_id = '{}' and status = 'DH'".format(dept)
	elif account_type == 'PMO':
		sql = "SELECT * FROM overtime_authorization WHERE status = 'PMO'"
	elif account_type == 'HHRD':
		sql = "SELECT * FROM overtime_authorization WHERE status = 'HHRD'"
	elif account_type == 'VP':
		sql = "SELECT * FROM overtime_authorization WHERE status = 'VP'"
	elif account_type == 'SP':
		sql = "SELECT * FROM overtime_authorization WHERE status = 'SP'"

	g.cur.execute(sql)
	return g.cur.fetchall()

def getPendingRequestsCount(table, account_type):
	sql = "SELECT count(*) FROM {} WHERE status = '{}'".format(table, account_type)
	g.cur.execute(sql)
	return g.cur.fetchall()[0]

def getTravelFormData(id):
	sql = "SELECT * FROM travel_order_form t JOIN department d ON d.id = t.department WHERE t.id = '{}'".format(id)
	g.cur.execute(sql)
	return g.cur.fetchall()[0]

def getLeaveFormData(id):
	sql = "SELECT * FROM leave_form WHERE id = '{}'".format(id)
	g.cur.execute(sql)
	return g.cur.fetchall()[0]
	
def getOvertimeFormData(id):
	sql = "SELECT * FROM overtime_authorization WHERE id = '{}'".format(id)
	g.cur.execute(sql)
	return g.cur.fetchall()[0]

def getMyForms(id, form_type):
	if form_type == 'Travel Form':
		sql = "SELECT * FROM travel_order_form WHERE user_id = '{}'".format(id)
	elif form_type == 'Leave Form':
		sql = "SELECT * FROM leave_form WHERE user_id = '{}'".format(id)
	elif form_type == 'Overtime Form':
		sql = "SELECT * FROM overtime_authorization WHERE user_id = '{}'".format(id)

	g.cur.execute(sql)
	return g.cur.fetchall()

if __name__ == "__main__":
	app.run(debug=True, host="0.0.0.0")