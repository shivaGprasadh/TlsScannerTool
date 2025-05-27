from datetime import datetime
from app import db
from sqlalchemy import Text, DateTime, Boolean, Integer, String, Float

class Domain(db.Model):
    id = db.Column(Integer, primary_key=True)
    hostname = db.Column(String(255), unique=True, nullable=False)
    active = db.Column(Boolean, default=True)
    created_at = db.Column(DateTime, default=datetime.utcnow)
    last_scanned = db.Column(DateTime)
    
    # Relationship to scan results
    scan_results = db.relationship('ScanResult', backref='domain', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Domain {self.hostname}>'

class ScanResult(db.Model):
    id = db.Column(Integer, primary_key=True)
    domain_id = db.Column(Integer, db.ForeignKey('domain.id'), nullable=False)
    scan_date = db.Column(DateTime, default=datetime.utcnow)
    
    # SSL/TLS Protocol Support
    sslv2_enabled = db.Column(Boolean, default=False)
    sslv3_enabled = db.Column(Boolean, default=False)
    tlsv1_0_enabled = db.Column(Boolean, default=False)
    tlsv1_1_enabled = db.Column(Boolean, default=False)
    tlsv1_2_enabled = db.Column(Boolean, default=False)
    tlsv1_3_enabled = db.Column(Boolean, default=False)
    
    # Security Features
    heartbleed_vulnerable = db.Column(Boolean, default=False)
    fallback_scsv_supported = db.Column(Boolean, default=False)
    secure_renegotiation = db.Column(Boolean, default=False)
    compression_enabled = db.Column(Boolean, default=False)
    
    # Certificate Information
    cert_signature_algorithm = db.Column(String(100))
    cert_key_strength = db.Column(Integer)
    cert_subject = db.Column(String(500))
    cert_issuer = db.Column(String(500))
    cert_not_before = db.Column(DateTime)
    cert_not_after = db.Column(DateTime)
    
    # Cipher Information
    weak_ciphers_count = db.Column(Integer, default=0)
    supported_ciphers = db.Column(Text)  # JSON string of cipher details
    
    # Overall Security Assessment
    security_score = db.Column(Float, default=0.0)  # 0-100 score
    security_grade = db.Column(String(2))  # A+, A, B, C, D, F
    has_deprecated_protocols = db.Column(Boolean, default=False)
    
    # Raw scan output for reference
    raw_output = db.Column(Text)
    scan_successful = db.Column(Boolean, default=True)
    error_message = db.Column(Text)
    
    def __repr__(self):
        return f'<ScanResult {self.domain.hostname} - {self.scan_date}>'
    
    @property
    def is_secure(self):
        """Check if the domain has secure SSL/TLS configuration"""
        return (not self.has_deprecated_protocols and 
                self.tlsv1_2_enabled and 
                not self.heartbleed_vulnerable and
                self.weak_ciphers_count == 0)
    
    @property
    def has_warnings(self):
        """Check if the domain has security warnings"""
        return (self.tlsv1_0_enabled or 
                self.tlsv1_1_enabled or 
                self.weak_ciphers_count > 0)
    
    def calculate_security_score(self):
        """Calculate a security score based on various factors"""
        score = 100.0
        
        # Deduct points for deprecated protocols
        if self.sslv2_enabled:
            score -= 30
        if self.sslv3_enabled:
            score -= 30
        if self.tlsv1_0_enabled:
            score -= 20
        if self.tlsv1_1_enabled:
            score -= 15
            
        # Deduct points for vulnerabilities
        if self.heartbleed_vulnerable:
            score -= 25
        if not self.secure_renegotiation:
            score -= 10
        if self.compression_enabled:
            score -= 5
            
        # Deduct points for weak ciphers
        score -= (self.weak_ciphers_count * 5)
        
        # Bonus points for modern protocols
        if self.tlsv1_3_enabled:
            score += 5
        if self.fallback_scsv_supported:
            score += 5
            
        # Ensure score is between 0 and 100
        self.security_score = max(0.0, min(100.0, score))
        
        # Assign letter grade
        if self.security_score >= 95:
            self.security_grade = 'A+'
        elif self.security_score >= 85:
            self.security_grade = 'A'
        elif self.security_score >= 75:
            self.security_grade = 'B'
        elif self.security_score >= 65:
            self.security_grade = 'C'
        elif self.security_score >= 50:
            self.security_grade = 'D'
        else:
            self.security_grade = 'F'
            
        return self.security_score

class ScanJob(db.Model):
    id = db.Column(Integer, primary_key=True)
    created_at = db.Column(DateTime, default=datetime.utcnow)
    started_at = db.Column(DateTime)
    completed_at = db.Column(DateTime)
    total_domains = db.Column(Integer, default=0)
    completed_domains = db.Column(Integer, default=0)
    failed_domains = db.Column(Integer, default=0)
    status = db.Column(String(20), default='pending')  # pending, running, completed, failed
    
    def __repr__(self):
        return f'<ScanJob {self.id} - {self.status}>'
    
    @property
    def progress_percentage(self):
        if self.total_domains == 0:
            return 0
        return (self.completed_domains / self.total_domains) * 100
