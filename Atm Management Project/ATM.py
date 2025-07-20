"""
Advanced ATM Management System
=============================

A comprehensive ATM simulation system with enhanced security, 
transaction logging, and user management features.

Author: ATM Development Team , Github Account ( py-hariom / hariom-jbnu )
Version: 2.0
Date: 2025
"""

import os
import datetime
import json
from typing import Optional, Dict, Any
import hashlib
import re


class ATMError(Exception):
    """Custom exception class for ATM-related errors."""
    pass


class SecurityManager:
    """Handles password hashing and security operations."""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using SHA-256.
        
        Args:
            password (str): Plain text password
            
        Returns:
            str: Hashed password
        """
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            password (str): Plain text password
            hashed (str): Hashed password
            
        Returns:
            bool: True if password matches, False otherwise
        """
        return SecurityManager.hash_password(password) == hashed
    
    @staticmethod
    def validate_pin(pin: str) -> bool:
        """
        Validate PIN format (4-6 digits).
        
        Args:
            pin (str): PIN to validate
            
        Returns:
            bool: True if valid format, False otherwise
        """
        return bool(re.match(r'^\d{4,6}$', pin))


class TransactionLogger:
    """Handles transaction logging and history."""
    
    def __init__(self, log_file: str):
        """
        Initialize transaction logger.
        
        Args:
            log_file (str): Path to transaction log file
        """
        self.log_file = log_file
        self._ensure_file_exists()
    
    def _ensure_file_exists(self) -> None:
        """Create log file if it doesn't exist."""
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                json.dump([], f)
    
    def log_transaction(self, transaction_type: str, amount: float = 0, 
                       balance_after: float = 0, status: str = "SUCCESS") -> None:
        """
        Log a transaction.
        
        Args:
            transaction_type (str): Type of transaction
            amount (float): Transaction amount
            balance_after (float): Balance after transaction
            status (str): Transaction status
        """
        try:
            with open(self.log_file, 'r') as f:
                transactions = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            transactions = []
        
        transaction = {
            "timestamp": datetime.datetime.now().isoformat(),
            "type": transaction_type,
            "amount": amount,
            "balance_after": balance_after,
            "status": status
        }
        
        transactions.append(transaction)
        
        # Keep only last 100 transactions
        transactions = transactions[-100:]
        
        with open(self.log_file, 'w') as f:
            json.dump(transactions, f, indent=2)
    
    def get_transaction_history(self, limit: int = 10) -> list:
        """
        Get recent transaction history.
        
        Args:
            limit (int): Number of recent transactions to return
            
        Returns:
            list: Recent transactions
        """
        try:
            with open(self.log_file, 'r') as f:
                transactions = json.load(f)
            return transactions[-limit:]
        except (json.JSONDecodeError, FileNotFoundError):
            return []


class ATM:
    """
    Advanced ATM Management System.
    
    Provides secure banking operations including balance inquiry,
    withdrawals, deposits, and transaction history.
    """
    
    # Class variables
    total_atm_holders = 0
    MAX_DAILY_WITHDRAWAL = 5000.0
    MIN_BALANCE = 0.0
    MAX_PIN_ATTEMPTS = 3
    
    def __init__(self, data_directory: str = "ATM_Data"):
        """
        Initialize ATM instance.
        
        Args:
            data_directory (str): Directory to store ATM data files
        """
        self.data_dir = data_directory
        self._create_data_directory()
        
        # File paths
        self.balance_file = os.path.join(self.data_dir, "balance.txt")
        self.password_file = os.path.join(self.data_dir, "password.txt")
        self.log_file = os.path.join(self.data_dir, "transactions.json")
        self.settings_file = os.path.join(self.data_dir, "settings.json")
        
        # Initialize components
        self.logger = TransactionLogger(self.log_file)
        self.security = SecurityManager()
        
        # Session variables
        self.is_authenticated = False
        self.failed_attempts = 0
        self.daily_withdrawal = 0.0
        self.last_withdrawal_date = None
        
        ATM.total_atm_holders += 1
        
        # Initialize files if they don't exist
        self._initialize_files()
    
    def _create_data_directory(self) -> None:
        """Create data directory if it doesn't exist."""
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
    
    def _initialize_files(self) -> None:
        """Initialize data files with default values if they don't exist."""
        if not os.path.exists(self.balance_file):
            with open(self.balance_file, 'w') as f:
                f.write("0.0")
        
        if not os.path.exists(self.password_file):
            # Default PIN: 1234 (hashed)
            default_pin = self.security.hash_password("1234")
            with open(self.password_file, 'w') as f:
                f.write(default_pin)
        
        if not os.path.exists(self.settings_file):
            default_settings = {
                "daily_withdrawal_limit": self.MAX_DAILY_WITHDRAWAL,
                "min_balance": self.MIN_BALANCE,
                "account_created": datetime.datetime.now().isoformat()
            }
            with open(self.settings_file, 'w') as f:
                json.dump(default_settings, f, indent=2)
    
    def _read_balance(self) -> float:
        """
        Read current balance from file.
        
        Returns:
            float: Current account balance
            
        Raises:
            ATMError: If unable to read balance
        """
        try:
            with open(self.balance_file, 'r') as f:
                balance_str = f.read().strip()
                return float(balance_str) if balance_str else 0.0
        except (FileNotFoundError, ValueError) as e:
            raise ATMError(f"Unable to read balance: {e}")
    
    def _write_balance(self, balance: float) -> None:
        """
        Write balance to file.
        
        Args:
            balance (float): Balance to write
            
        Raises:
            ATMError: If unable to write balance
        """
        try:
            with open(self.balance_file, 'w') as f:
                f.write(f"{balance:.2f}")
        except Exception as e:
            raise ATMError(f"Unable to save balance: {e}")
    
    def _read_password_hash(self) -> str:
        """
        Read password hash from file.
        
        Returns:
            str: Password hash
            
        Raises:
            ATMError: If unable to read password
        """
        try:
            with open(self.password_file, 'r') as f:
                return f.read().strip()
        except FileNotFoundError:
            raise ATMError("Password file not found")
    
    def _write_password_hash(self, password_hash: str) -> None:
        """
        Write password hash to file.
        
        Args:
            password_hash (str): Hashed password to write
            
        Raises:
            ATMError: If unable to write password
        """
        try:
            with open(self.password_file, 'w') as f:
                f.write(password_hash)
        except Exception as e:
            raise ATMError(f"Unable to save password: {e}")
    
    def _check_daily_limit(self) -> None:
        """Reset daily withdrawal counter if it's a new day."""
        today = datetime.date.today()
        if self.last_withdrawal_date != today:
            self.daily_withdrawal = 0.0
            self.last_withdrawal_date = today
    
    def authenticate(self, pin: str) -> bool:
        """
        Authenticate user with PIN.
        
        Args:
            pin (str): User's PIN
            
        Returns:
            bool: True if authentication successful
            
        Raises:
            ATMError: If too many failed attempts
        """
        if self.failed_attempts >= self.MAX_PIN_ATTEMPTS:
            self.logger.log_transaction("AUTH_BLOCKED", status="FAILED")
            raise ATMError("Account temporarily locked due to multiple failed attempts")
        
        if not self.security.validate_pin(pin):
            self.failed_attempts += 1
            self.logger.log_transaction("AUTH_INVALID_FORMAT", status="FAILED")
            return False
        
        try:
            stored_hash = self._read_password_hash()
            if self.security.verify_password(pin, stored_hash):
                self.is_authenticated = True
                self.failed_attempts = 0
                self.logger.log_transaction("LOGIN", status="SUCCESS")
                return True
            else:
                self.failed_attempts += 1
                self.logger.log_transaction("AUTH_FAILED", status="FAILED")
                return False
        except ATMError as e:
            self.logger.log_transaction("AUTH_ERROR", status="ERROR")
            raise e
    
    def check_balance(self) -> Dict[str, Any]:
        """
        Check account balance.
        
        Returns:
            Dict[str, Any]: Balance information
            
        Raises:
            ATMError: If not authenticated or unable to read balance
        """
        if not self.is_authenticated:
            raise ATMError("Authentication required")
        
        try:
            balance = self._read_balance()
            self.logger.log_transaction("BALANCE_INQUIRY", balance_after=balance)
            return {
                "balance": balance,
                "formatted_balance": f"${balance:.2f}",
                "timestamp": datetime.datetime.now().isoformat()
            }
        except ATMError:
            self.logger.log_transaction("BALANCE_INQUIRY", status="ERROR")
            raise
    
    def withdraw(self, amount: float) -> Dict[str, Any]:
        """
        Withdraw money from account.
        
        Args:
            amount (float): Amount to withdraw
            
        Returns:
            Dict[str, Any]: Withdrawal result
            
        Raises:
            ATMError: If withdrawal conditions not met
        """
        if not self.is_authenticated:
            raise ATMError("Authentication required")
        
        if amount <= 0:
            raise ATMError("Withdrawal amount must be positive")
        
        if amount % 5 != 0:  # ATMs typically dispense multiples of 5
            raise ATMError("Amount must be in multiples of $5")
        
        self._check_daily_limit()
        
        if self.daily_withdrawal + amount > self.MAX_DAILY_WITHDRAWAL:
            remaining = self.MAX_DAILY_WITHDRAWAL - self.daily_withdrawal
            raise ATMError(f"Daily withdrawal limit exceeded. Remaining limit: ${remaining:.2f}")
        
        try:
            current_balance = self._read_balance()
            
            if amount > current_balance:
                self.logger.log_transaction("WITHDRAWAL", amount, current_balance, "INSUFFICIENT_FUNDS")
                raise ATMError(f"Insufficient funds. Current balance: ${current_balance:.2f}")
            
            new_balance = current_balance - amount
            
            if new_balance < self.MIN_BALANCE:
                raise ATMError(f"Transaction would result in balance below minimum (${self.MIN_BALANCE:.2f})")
            
            self._write_balance(new_balance)
            self.daily_withdrawal += amount
            
            self.logger.log_transaction("WITHDRAWAL", amount, new_balance)
            
            return {
                "amount_withdrawn": amount,
                "remaining_balance": new_balance,
                "formatted_amount": f"${amount:.2f}",
                "formatted_balance": f"${new_balance:.2f}",
                "daily_withdrawal_used": f"${self.daily_withdrawal:.2f}",
                "daily_limit_remaining": f"${self.MAX_DAILY_WITHDRAWAL - self.daily_withdrawal:.2f}",
                "timestamp": datetime.datetime.now().isoformat()
            }
            
        except ATMError:
            self.logger.log_transaction("WITHDRAWAL", amount, status="ERROR")
            raise
    
    def deposit(self, amount: float) -> Dict[str, Any]:
        """
        Deposit money to account.
        
        Args:
            amount (float): Amount to deposit
            
        Returns:
            Dict[str, Any]: Deposit result
            
        Raises:
            ATMError: If deposit conditions not met
        """
        if not self.is_authenticated:
            raise ATMError("Authentication required")
        
        if amount <= 0:
            raise ATMError("Deposit amount must be positive")
        
        if amount > 10000:  # Maximum single deposit
            raise ATMError("Maximum single deposit is $10,000")
        
        try:
            current_balance = self._read_balance()
            new_balance = current_balance + amount
            
            self._write_balance(new_balance)
            self.logger.log_transaction("DEPOSIT", amount, new_balance)
            
            return {
                "amount_deposited": amount,
                "new_balance": new_balance,
                "formatted_amount": f"${amount:.2f}",
                "formatted_balance": f"${new_balance:.2f}",
                "timestamp": datetime.datetime.now().isoformat()
            }
            
        except ATMError:
            self.logger.log_transaction("DEPOSIT", amount, status="ERROR")
            raise
    
    def change_pin(self, old_pin: str, new_pin: str) -> bool:
        """
        Change account PIN.
        
        Args:
            old_pin (str): Current PIN
            new_pin (str): New PIN
            
        Returns:
            bool: True if PIN changed successfully
            
        Raises:
            ATMError: If PIN change fails
        """
        if not self.is_authenticated:
            raise ATMError("Authentication required")
        
        if not self.security.validate_pin(new_pin):
            raise ATMError("New PIN must be 4-6 digits")
        
        if old_pin == new_pin:
            raise ATMError("New PIN must be different from current PIN")
        
        try:
            stored_hash = self._read_password_hash()
            if not self.security.verify_password(old_pin, stored_hash):
                self.logger.log_transaction("PIN_CHANGE", status="UNAUTHORIZED")
                raise ATMError("Current PIN is incorrect")
            
            new_hash = self.security.hash_password(new_pin)
            self._write_password_hash(new_hash)
            
            self.logger.log_transaction("PIN_CHANGE", status="SUCCESS")
            return True
            
        except ATMError:
            self.logger.log_transaction("PIN_CHANGE", status="ERROR")
            raise
    
    def get_transaction_history(self, limit: int = 10) -> list:
        """
        Get transaction history.
        
        Args:
            limit (int): Number of transactions to retrieve
            
        Returns:
            list: Transaction history
            
        Raises:
            ATMError: If not authenticated
        """
        if not self.is_authenticated:
            raise ATMError("Authentication required")
        
        return self.logger.get_transaction_history(limit)
    
    def logout(self) -> None:
        """Logout current session."""
        if self.is_authenticated:
            self.logger.log_transaction("LOGOUT", status="SUCCESS")
            self.is_authenticated = False


def display_menu() -> None:
    """Display main menu options."""
    print("\n" + "="*50)
    print("           ATM MANAGEMENT SYSTEM")
    print("="*50)
    print("1. Check Balance")
    print("2. Withdraw Money")
    print("3. Deposit Money")
    print("4. Change PIN")
    print("5. Transaction History")
    print("6. Account Information")
    print("7. Logout")
    print("-"*50)


def display_transaction_history(transactions: list) -> None:
    """Display formatted transaction history."""
    if not transactions:
        print("No transactions found.")
        return
    
    print("\n" + "="*70)
    print("                    TRANSACTION HISTORY")
    print("="*70)
    print(f"{'Date/Time':<20} {'Type':<15} {'Amount':<12} {'Status':<10}")
    print("-"*70)
    
    for trans in reversed(transactions):  # Most recent first
        timestamp = trans.get('timestamp', '')[:19].replace('T', ' ')
        trans_type = trans.get('type', '')
        amount = f"${trans.get('amount', 0):.2f}" if trans.get('amount') else "N/A"
        status = trans.get('status', '')
        
        print(f"{timestamp:<20} {trans_type:<15} {amount:<12} {status:<10}")


def main():
    """Main application entry point."""
    print("Welcome to Advanced ATM Management System")
    print("Default PIN: 1234 (Please change after first login)")
    
    atm = ATM()
    
    try:
        # Authentication loop
        while not atm.is_authenticated:
            try:
                pin = input("\nEnter your PIN: ").strip()
                if atm.authenticate(pin):
                    print("✓ Authentication successful!")
                    break
                else:
                    print("✗ Invalid PIN. Please try again.")
            except ATMError as e:
                print(f"✗ Error: {e}")
                return
            except KeyboardInterrupt:
                print("\nThank you for using ATM!")
                return
        
        # Main application loop
        while atm.is_authenticated:
            try:
                display_menu()
                choice = input("Select an option (1-7): ").strip()
                
                if choice == '1':
                    # Check Balance
                    result = atm.check_balance()
                    print(f"\n✓ Current Balance: {result['formatted_balance']}")
                
                elif choice == '2':
                    # Withdraw Money
                    try:
                        amount = float(input("Enter withdrawal amount: $"))
                        result = atm.withdraw(amount)
                        print(f"\n✓ Withdrawal Successful!")
                        print(f"Amount Withdrawn: {result['formatted_amount']}")
                        print(f"Remaining Balance: {result['formatted_balance']}")
                        print(f"Daily Limit Remaining: {result['daily_limit_remaining']}")
                    except ValueError:
                        print("✗ Please enter a valid amount")
                
                elif choice == '3':
                    # Deposit Money
                    try:
                        amount = float(input("Enter deposit amount: $"))
                        result = atm.deposit(amount)
                        print(f"\n✓ Deposit Successful!")
                        print(f"Amount Deposited: {result['formatted_amount']}")
                        print(f"New Balance: {result['formatted_balance']}")
                    except ValueError:
                        print("✗ Please enter a valid amount")
                
                elif choice == '4':
                    # Change PIN
                    old_pin = input("Enter current PIN: ").strip()
                    new_pin = input("Enter new PIN (4-6 digits): ").strip()
                    confirm_pin = input("Confirm new PIN: ").strip()
                    
                    if new_pin != confirm_pin:
                        print("✗ New PIN confirmation doesn't match")
                    else:
                        if atm.change_pin(old_pin, new_pin):
                            print("✓ PIN changed successfully!")
                
                elif choice == '5':
                    # Transaction History
                    limit = 10
                    try:
                        limit_input = input(f"Number of transactions to show (default {limit}): ").strip()
                        if limit_input:
                            limit = int(limit_input)
                    except ValueError:
                        pass
                    
                    transactions = atm.get_transaction_history(limit)
                    display_transaction_history(transactions)
                
                elif choice == '6':
                    # Account Information
                    balance_info = atm.check_balance()
                    print(f"\n{'='*40}")
                    print("         ACCOUNT INFORMATION")
                    print(f"{'='*40}")
                    print(f"Current Balance: {balance_info['formatted_balance']}")
                    print(f"Daily Withdrawal Used: ${atm.daily_withdrawal:.2f}")
                    print(f"Daily Limit Remaining: ${atm.MAX_DAILY_WITHDRAWAL - atm.daily_withdrawal:.2f}")
                    print(f"Total ATM Holders: {ATM.total_atm_holders}")
                
                elif choice == '7':
                    # Logout
                    atm.logout()
                    print("✓ Logged out successfully!")
                    break
                
                else:
                    print("✗ Invalid option. Please select 1-7.")
                
                # Pause for user to read output
                input("\nPress Enter to continue...")
                
            except ATMError as e:
                print(f"✗ Error: {e}")
                input("Press Enter to continue...")
            except KeyboardInterrupt:
                print("\n\nLogging out...")
                atm.logout()
                break
            except Exception as e:
                print(f"✗ Unexpected error: {e}")
                input("Press Enter to continue...")
    
    finally:
        print("\nThank you for using Advanced ATM Management System!")
        print("Have a great day!")


if __name__ == "__main__":
    main()
