from getpass import getpass


def prompt_yes_no(question):
    while True:
        answer = input(f"{question} [y/n]: ").lower()
        if answer in ["y", "yes"]:
            return True
        elif answer in ["n", "no"]:
            return False
        else:
            print("Invalid answer. Please answer with 'yes' or 'no'.")


def prompt_non_empty(question, secret=False):
    while True:
        if secret:
            answer = getpass(f"{question} [input is hidden]\n")
        else:
            answer = input(f"{question}\n")

        answer = answer.strip()

        if answer != "":
            return answer
        else:
            print("Answer cannot be empty.")
