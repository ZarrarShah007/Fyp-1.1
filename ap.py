import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import yaml
import logging
from tkinter.scrolledtext import ScrolledText
import boto3

# AWS Credentials if it didn't work for other computer.
#  Set AWS credentials
# aws_access_key_id = 'YOUR_ACCESS_KEY_ID'
# aws_secret_access_key = 'YOUR_SECRET_ACCESS_KEY'
#
# # Set AWS region
# region = 'YOUR_AWS_REGION'
#
# # Bucket name
# bucket_name = 'project-log-details'
#
# # Configure AWS session
#  = boto3.Session(
#     aws_access_key_id=aws_access_key_id,
#     aws_secret_access_key=aws_secret_access_key,
#     region_name=region
# )

# Create an S3 client
s3 = boto3.client('s3')

# Set up logging configuration
logging.basicConfig(level=logging.INFO)


# Define YAML constructor for '!Ref' tag
def ref_constructor(loader, node):
    return loader.construct_scalar(node)


yaml.SafeLoader.add_constructor(u'!Ref', ref_constructor)


# Function to analyze security groups based on defined criteria
def analyze_security_groups(yaml_data):
    issues = []

    for resource_name, resource_details in yaml_data.get("Resources", {}).items():
        if resource_details.get("Type") == "AWS::EC2::SecurityGroup":
            for ingress_rule in resource_details.get("Properties", {}).get("SecurityGroupIngress", []):
                if ingress_rule.get("CidrIp") == "0.0.0.0/0":
                    issues.append(("Security group allows traffic from '0.0.0.0/0'",
                                   f"Security Group: {resource_name}, Rule: {ingress_rule}"))
                if ingress_rule.get("FromPort") == 22 or ingress_rule.get("ToPort") == 22:
                    issues.append(("Security group allows SSH traffic (port 22)",
                                   f"Security Group: {resource_name}, Rule: {ingress_rule}"))
                if ingress_rule.get("IpProtocol") == "-1":
                    issues.append(("Security group allows all traffic",
                                   f"Security Group: {resource_name}, Rule: {ingress_rule}"))
                if "SourceSecurityGroupId" in ingress_rule:
                    issues.append(("Security group allows traffic from another security group",
                                   f"Security Group: {resource_name}, Rule: {ingress_rule}"))

    return issues


# Function to analyze resource based on defined criteria
def analyze_resource(resource_name, resource_details, criteria):
    issues = []

    for rule_name, rule_condition, rule_details in criteria:
        try:
            if rule_condition(resource_details):
                issues.append((f"{rule_name} issue in resource '{resource_name}'", rule_details))
        except Exception as e:
            logging.error(f"Error evaluating rule '{rule_name}' for resource '{resource_name}': {str(e)}")

    return issues


# Function to analyze YAML data based on defined criteria
def analyze_yaml(yaml_data, criteria):
    issues = []

    for resource_name, resource_details in yaml_data.get("Resources", {}).items():
        resource_issues = analyze_resource(resource_name, resource_details, criteria)
        issues.extend(resource_issues)

    return issues


# Function to print issues
def print_issues(issues, pipeline_fail_threshold=0):
    result_output = "\nIssues:\n"
    for issue, rule_details in issues:
        result_output += f"- {issue}\n"
        result_output += f"  Rule Details: {rule_details}\n"

    if len(issues) >= pipeline_fail_threshold:
        result_output += "\nThe pipeline will fail due to the identified issues."
    else:
        result_output += "\nThe pipeline will not fail."

    return result_output


# Function to log issues to a file
def log_issues(issues, log_file="pipeline_issues.log"):
    logging.info("Writing issues to log file.")
    with open(log_file, "a") as log:
        for issue, rule_details in issues:
            log.write(f"{issue}\n")
            log.write(f"  Rule Details: {rule_details}\n")


# Function to write issues to a report file
def write_report(issues, report_file="pipeline_report.txt"):
    logging.info("Writing issues to report file.")
    with open(report_file, "w") as report:
        report.write("Pipeline Report\n")
        report.write("=" * 15 + "\n\n")
        if issues:
            report.write("Issues:\n")
            for issue, rule_details in issues:
                report.write(f"- {issue}\n")
                report.write(f"  Rule Details: {rule_details}\n")
        else:
            report.write("No issues found.\n")


# Function to show the result in a Tkinter dialog with template selection UI
def show_result(template_path, criteria):
    try:
        if template_path:
            with open(template_path, "r") as file:
                yaml_data = yaml.safe_load(file)

            security_group_issues = analyze_security_groups(yaml_data)

            identified_issues = analyze_yaml(yaml_data, criteria)

            # Incorporate security group issues into identified issues
            identified_issues.extend(security_group_issues)

            result_output = print_issues(
                identified_issues, pipeline_fail_threshold=1)

            messagebox.showinfo("Result", result_output)

            log_issues(identified_issues)
            write_report(identified_issues)

            s3.upload_file("pipeline_report.txt", 'project-log-details', 'pipeline_report.txt')
            messagebox.showinfo("Success", "Report uploaded to S3 bucket.")

    except FileNotFoundError:
        logging.error("YAML file not found.")
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")


def open_code():
    # You can replace "main_code.py" with the actual file name you want to open
    with open("ap.py", "r") as file:
        code_content = file.read()

    # Create a frame to contain the code text and buttons
    code_frame = tk.Frame(customization_page)
    code_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

    # Create a text widget to display the code
    code_text = ScrolledText(code_frame, wrap=tk.WORD)
    code_text.insert(tk.END, code_content)
    code_text.pack(expand=True, fill=tk.BOTH)

    # Add padding to the bottom of the frame
    code_frame.grid_columnconfigure(0, weight=1)
    code_frame.grid_rowconfigure(1, weight=1)

    # Function to save changes made to the code
    def save_changes(code_text):
        # Get the modified code from the text widget
        modified_code = code_text.get("1.0", tk.END)

        # Save the modified code to the file
        with open("ap.py", "w") as file:
            file.write(modified_code)

        messagebox.showinfo("Success", "Changes saved successfully.")

    # Function to discard changes made to the code
    def discard_changes(code_text):
        # Clear the text widget to discard changes
        code_text.delete("1.0", tk.END)
        open_code()  # Reload the original code

        messagebox.showinfo("Success", "Changes discarded.")

    # Create buttons for Save and Discard
    save_button = tk.Button(code_frame, text="Save", command=lambda: save_changes(code_text))
    save_button.pack(side=tk.LEFT, padx=5, pady=5)

    discard_button = tk.Button(code_frame, text="Discard", command=lambda: discard_changes(code_text))
    discard_button.pack(side=tk.LEFT, padx=5, pady=5)


# Function to open the customization GUI
def open_customization():
    try:
        with open("ap.py", "r") as customization_file:
            customization_content = customization_file.read()

        customization_window = tk.Toplevel(root)
        customization_window.title("Customization")

        customization_text = ScrolledText(customization_window, wrap=tk.WORD)
        customization_text.insert(tk.END, customization_content)
        customization_text.pack(expand=True, fill=tk.BOTH)

    except FileNotFoundError:
        messagebox.showerror("Error", "Customization file not found.")


# Function to open the reports file inside the GUI frame
def open_reports():
    try:
        with open("pipeline_report.txt", "r") as report_file:
            reports_content = report_file.read()

        # Clear any existing widgets in the show_report_page
        for widget in show_report_page.winfo_children():
            widget.destroy()

        # Create a text widget to display the reports
        reports_text = ScrolledText(show_report_page, wrap=tk.WORD)
        reports_text.insert(tk.END, reports_content)
        reports_text.pack(expand=True, fill=tk.BOTH)

    except FileNotFoundError:
        messagebox.showerror("Error", "Reports file not found.")


# Function to open the logs file inside the GUI frame
def open_logs():
    try:
        with open("pipeline_issues.log", "r") as log_file:
            logs_content = log_file.read()

        # Clear any existing widgets in the show_log_page
        for widget in show_log_page.winfo_children():
            widget.destroy()

        # Create a text widget to display the logs
        logs_text = ScrolledText(show_log_page, wrap=tk.WORD)
        logs_text.insert(tk.END, logs_content)
        logs_text.pack(expand=True, fill=tk.BOTH)

    except FileNotFoundError:
        messagebox.showerror("Error", "Logs file not found.")


def open_file(parent_frame):
    file_path = filedialog.askopenfilename(parent=parent_frame)
    # Process the selected file path as needed
    print("Selected file:", file_path)


# Function to show the template selection UI instead of opening a new window
def show_template_selection_gui(root):
    # Variables for checkboxes
    cidr_ip_var = tk.BooleanVar()
    ssh_traffic_var = tk.BooleanVar()
    all_traffic_var = tk.BooleanVar()
    sg_traffic_var = tk.BooleanVar()

    # Checkboxes for selecting validation checks
    tk.Checkbutton(root, text="CIDR IP check", variable=cidr_ip_var).pack()
    tk.Checkbutton(root, text="SSH Traffic check", variable=ssh_traffic_var).pack()
    tk.Checkbutton(root, text="All Traffic check", variable=all_traffic_var).pack()
    tk.Checkbutton(root, text="Security Group Traffic check", variable=sg_traffic_var).pack()

    tk.Button(root, text="Run Analysis",
              command=lambda: run_analysis(cidr_ip_var, ssh_traffic_var, all_traffic_var, sg_traffic_var)).pack()

    root.mainloop()


# Function to run the analysis based on selected criteria
def run_analysis(cidr_ip_var, ssh_traffic_var, all_traffic_var, sg_traffic_var, template_path):
    criteria = []

    if not cidr_ip_var.get() and not ssh_traffic_var.get() and not all_traffic_var.get() and not sg_traffic_var.get():
        criteria.append(("Security", lambda resource: "SecurityGroup" in resource.get("Type", "") and any(
            rule.get("CidrIp", "") == "0.0.0.0/0" for rule in
            resource.get("Properties", {}).get("SecurityGroupIngress", [])
        ),
                         "Security group allows traffic from '0.0.0.0/0'"))
        criteria.append(("Medium", lambda resource: "SecurityGroup" in resource.get("Type", "") and any(
            (rule.get("FromPort", 0) == 22 or rule.get("ToPort", 0) == 22) and rule.get("IpProtocol",
                                                                                        "") == "tcp"
            for rule in resource.get("Properties", {}).get("SecurityGroupIngress", [])
        ),
                         "Security group allows SSH traffic (port 22)"))
        criteria.append(("Critical", lambda resource: "SecurityGroup" in resource.get("Type", "") and any(
            rule.get("IpProtocol") == "-1" for rule in
            resource.get("Properties", {}).get("SecurityGroupIngress", [])
        ),
                         "Security group allows all traffic"))
        criteria.append(("Medium", lambda resource: "SecurityGroup" in resource.get("Type", "") and any(
            "SourceSecurityGroupId" in rule for rule in
            resource.get("Properties", {}).get("SecurityGroupIngress", [])
        ),
                         "Security group allows traffic from another security group"))

    if cidr_ip_var.get():
        criteria.append(("Security", lambda resource: "SecurityGroup" in resource.get("Type", "") and any(
            rule.get("CidrIp", "") == "0.0.0.0/0" for rule in
            resource.get("Properties", {}).get("SecurityGroupIngress", [])
        ),
                         "Security group allows traffic from '0.0.0.0/0'"))

    if ssh_traffic_var.get():
        criteria.append(("Medium", lambda resource: "SecurityGroup" in resource.get("Type", "") and any(
            (rule.get("FromPort", 0) == 22 or rule.get("ToPort", 0) == 22) and rule.get("IpProtocol",
                                                                                        "") == "tcp"
            for rule in resource.get("Properties", {}).get("SecurityGroupIngress", [])
        ),
                         "Security group allows SSH traffic (port 22)"))

    if all_traffic_var.get():
        criteria.append(("Critical", lambda resource: "SecurityGroup" in resource.get("Type", "") and any(
            rule.get("IpProtocol") == "-1" for rule in
            resource.get("Properties", {}).get("SecurityGroupIngress", [])
        ),
                         "Security group allows all traffic"))

    if sg_traffic_var.get():
        criteria.append(("Medium", lambda resource: "SecurityGroup" in resource.get("Type", "") and any(
            "SourceSecurityGroupId" in rule for rule in
            resource.get("Properties", {}).get("SecurityGroupIngress", [])
        ),
                         "Security group allows traffic from another security group"))

    show_result(template_path, criteria)


# Function to select a template file
def select_template(root, cidr_ip_var, ssh_traffic_var, all_traffic_var, sg_traffic_var, select_template_button):
    template_path = filedialog.askopenfilename(
        initialdir="./content", title="Select Template File",
        filetypes=(("YAML files", "*.yaml"), ("All files", "*.*")))

    # If a template file is selected, update the text of the button to display the selected file
    if template_path:
        select_template_button.config(text=f"Selected Template: {template_path}")

        # Run the analysis with the selected template file and criteria
        run_analysis(cidr_ip_var, ssh_traffic_var, all_traffic_var, sg_traffic_var, template_path)


# GUI setup
root = tk.Tk()
root.title("Security Testing Tool")
root.geometry("720x650")
root.configure(background='Brown')

# Create a custom style
style = ttk.Style()

# Set the background color for the label
style.configure('HomeLabel.TLabel', background='sky blue')

# Home page label
home_label = ttk.Label(root, text="Welcome To Security Testing Tool", font=('Helvetica', 28, 'bold'),
                       style='HomeLabel.TLabel')
home_label.pack(pady=30)


# Function to navigate to different pages
def navigate_to(page):
    page.tkraise()


# Function to navigate to the home page
def navigate_to_home():
    navigate_to(home_page)


# Function to navigate to the "Run Code" page
def navigate_to_run_code():
    navigate_to(run_code_page)


# Function to navigate to the "Customization" page
def navigate_to_customization():
    navigate_to(customization_page)


# Function to navigate to the "Show Report" page
def navigate_to_show_report():
    navigate_to(show_report_page)


# Function to navigate to the "Show Log" page
def navigate_to_show_log():
    navigate_to(show_log_page)


# Create a container to hold different pages
container = tk.Frame(root)
container.pack(fill=tk.BOTH, expand=True)

# Create a container to hold different pages
container = tk.Frame(root, background='White')  # Change background color here
container.pack(fill=tk.BOTH, expand=True)

# Create different pages
home_page = tk.Frame(container, background='White')
run_code_page = tk.Frame(container, background='White')
customization_page = tk.Frame(container, background='White')
show_report_page = tk.Frame(container, background='White')
show_log_page = tk.Frame(container, background='White')

# Add pages to the container
for page in (home_page, run_code_page, customization_page, show_report_page, show_log_page):
    page.grid(row=0, column=0, sticky="nsew")

# Create buttons for navigation
home_button = tk.Button(root, text="Home", command=navigate_to_home, font=('Helvetica', 14))
home_button.pack(side=tk.LEFT, padx=20, pady=20)

# Button to navigate to the "Run Code" page
run_code_button = tk.Button(root, text="Run Code", command=navigate_to_run_code, font=('Helvetica', 14))
run_code_button.pack(side=tk.LEFT, padx=20, pady=20)

# Button to navigate to the "Customization" page
customization_button = tk.Button(root, text="Customization", command=navigate_to_customization, font=('Helvetica', 14))
customization_button.pack(side=tk.LEFT, padx=20, pady=20)

# Customization page elements
customization_label = ttk.Label(customization_page, text="Customization", font=('Helvetica', 20, 'bold'))
customization_label.pack(pady=24)

# Button to navigate to the "Show Report" page
show_report_button = tk.Button(root, text="Show Report", command=navigate_to_show_report, font=('Helvetica', 14))
show_report_button.pack(side=tk.LEFT, padx=20, pady=20)

# Button to navigate to the "Show Log" page
show_log_button = tk.Button(root, text="Show Log", command=navigate_to_show_log, font=('Helvetica', 14))
show_log_button.pack(side=tk.LEFT, padx=20, pady=20)

## Home page elements
home_label = ttk.Label(home_page, text="Home", font=('Helvetica', 20, 'bold'))

home_label.pack(pady=24, anchor="center")
# Description label
description_label = ttk.Label(home_page,
                              text="Security Testing Tool Is Designed to Detect vulnerabilities and enhance security posture.",
                              font=('Helvetica', 11))
description_label.pack(pady=10, anchor="s")
description_label = ttk.Label(home_page,
                              text="Customize tests, obtain detailed insights, and bolster defenses against cyber threats.",
                              font=('Helvetica', 11))
description_label.pack(pady=10, anchor="s")
description_label = ttk.Label(home_page, text="The Tool contain following featuress.", font=('Helvetica', 11))
description_label.pack(pady=10, anchor="s")

# Bullet points
bullet_points = [
    "Customize tests to fit your needs",
    "Obtain detailed insights into security vulnerabilities",
    "Bolster defenses against cyber threats",
    "Access a range of security features for comprehensive testing"
]

# Define a custom style for the bullet points
style.configure('Bullet.TLabel', foreground='blue')

for point in bullet_points:
    bullet_label = ttk.Label(home_page, text="• " + point, font=('Helvetica', 11), style='Bullet.TLabel')
    bullet_label.pack(anchor="w")

# Button to edit code
edit_code_button = tk.Button(customization_page, text="Edit Code", command=open_code, font=('Helvetica', 14))
edit_code_button.pack(pady=10)

# Run Code page elements
run_code_label = ttk.Label(run_code_page, text="Run Code", font=('Helvetica', 20, 'bold'))
run_code_label.pack(pady=24)

# Show Report page elements
show_report_label = ttk.Label(show_report_page, text="Show Report", font=('Helvetica', 20, 'bold'))
show_report_label.pack(pady=24)

# Show Log page elements
show_log_label = ttk.Label(show_log_page, text="Show Log", font=('Helvetica', 20, 'bold'))
show_log_label.pack(pady=24)

# Button to open logs in the GUI frame
open_logs_button = tk.Button(show_log_page, text="Open Logs", command=open_logs, font=('Helvetica', 12))
open_logs_button.pack(pady=10, anchor="center")

# Button to open reports in the GUI frame
open_reports_button = tk.Button(show_report_page, text="Open Reports", command=open_reports, font=('Helvetica', 12))
open_reports_button.pack(pady=10, anchor="center")

# Variables for checkboxes
cidr_ip_var = tk.BooleanVar()
ssh_traffic_var = tk.BooleanVar()
all_traffic_var = tk.BooleanVar()
sg_traffic_var = tk.BooleanVar()

# Checkboxes for selecting validation checks
tk.Checkbutton(run_code_page, text="CIDR IP check", font=('Helvetica', 10, 'bold'), variable=cidr_ip_var).pack(
    anchor="center")
tk.Checkbutton(run_code_page, text="SSH Traffic check", font=('Helvetica', 10, 'bold'), variable=ssh_traffic_var).pack(
    anchor="center")
tk.Checkbutton(run_code_page, text="All Traffic check", font=('Helvetica', 10, 'bold'), variable=all_traffic_var).pack(
    anchor="center")
tk.Checkbutton(run_code_page, text="Security Group Traffic check", font=('Helvetica', 10, 'bold'),
               variable=sg_traffic_var).pack(anchor="center")

# Button to select template
select_template_button = tk.Button(run_code_page, text="Select Template", font=('Helvetica', 12),
                                   command=lambda: select_template(root, cidr_ip_var, ssh_traffic_var, all_traffic_var,
                                                                   sg_traffic_var, select_template_button))
select_template_button.pack(pady=24)

# Start with the home page
navigate_to_home()

# Start the Tkinter event loop
root.mainloop()