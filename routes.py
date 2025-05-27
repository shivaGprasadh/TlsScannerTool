import csv
import io
import json
import threading
from datetime import datetime
from flask import render_template, request, redirect, url_for, flash, make_response, jsonify
from app import app, db
from models import Domain, ScanResult, ScanJob
from ssl_scanner import SSLScanner

scanner = SSLScanner()

@app.route('/')
def index():
    """Dashboard showing overview of all domains"""
    # Get summary statistics
    total_domains = Domain.query.filter_by(active=True).count()

    # Get latest scan results for each domain
    latest_scans = db.session.query(ScanResult).join(Domain).filter(
        Domain.active == True
    ).order_by(ScanResult.scan_date.desc()).limit(10).all()

    # Calculate summary stats
    scanned_domains = db.session.query(Domain).join(ScanResult).filter(
        Domain.active == True
    ).distinct().count()

    # Count domains by security grade
    grade_counts = {}
    security_stats = db.session.query(
        ScanResult.security_grade, 
        db.func.count(ScanResult.id)
    ).join(Domain).filter(
        Domain.active == True
    ).group_by(ScanResult.security_grade).all()

    for grade, count in security_stats:
        grade_counts[grade or 'Not Scanned'] = count

    # Count domains with deprecated protocols
    deprecated_count = db.session.query(ScanResult).join(Domain).filter(
        Domain.active == True,
        ScanResult.has_deprecated_protocols == True
    ).count()

    # Get current scan job status
    current_job = ScanJob.query.filter_by(status='running').first()

    return render_template('index.html',
                         total_domains=total_domains,
                         scanned_domains=scanned_domains,
                         latest_scans=latest_scans,
                         grade_counts=grade_counts,
                         deprecated_count=deprecated_count,
                         current_job=current_job)

@app.route('/domains')
def domains():
    """Domain management page"""
    page = request.args.get('page', 1, type=int)
    per_page = 20

    domains = Domain.query.filter_by(active=True).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('domains.html', domains=domains)

@app.route('/domains/add', methods=['POST'])
def add_domain():
    """Add a new domain"""
    hostname = request.form.get('hostname', '').strip()

    if not hostname:
        flash('Hostname is required', 'error')
        return redirect(url_for('domains'))

    # Check if domain already exists
    existing = Domain.query.filter_by(hostname=hostname).first()
    if existing:
        if existing.active:
            flash(f'Domain {hostname} already exists', 'error')
        else:
            existing.active = True
            db.session.commit()
            flash(f'Domain {hostname} reactivated', 'success')
        return redirect(url_for('domains'))

    # Create new domain
    domain = Domain(hostname=hostname)
    db.session.add(domain)
    db.session.commit()

    flash(f'Domain {hostname} added successfully', 'success')
    return redirect(url_for('domains'))

@app.route('/domains/bulk_add', methods=['POST'])
def bulk_add_domains():
    """Add multiple domains from textarea"""
    domains_text = request.form.get('domains_text', '')

    if not domains_text:
        flash('No domains provided', 'error')
        return redirect(url_for('domains'))

    # Parse domains from text (one per line)
    hostnames = [line.strip() for line in domains_text.split('\n') if line.strip()]

    added_count = 0
    updated_count = 0

    for hostname in hostnames:
        existing = Domain.query.filter_by(hostname=hostname).first()
        if existing:
            if not existing.active:
                existing.active = True
                updated_count += 1
        else:
            domain = Domain(hostname=hostname)
            db.session.add(domain)
            added_count += 1

    db.session.commit()

    flash(f'Added {added_count} new domains, reactivated {updated_count} domains', 'success')
    return redirect(url_for('domains'))

@app.route('/domains/<int:domain_id>/delete', methods=['POST'])
def delete_domain(domain_id):
    """Soft delete a domain"""
    domain = Domain.query.get_or_404(domain_id)
    domain.active = False
    db.session.commit()

    flash(f'Domain {domain.hostname} deleted', 'success')
    return redirect(url_for('domains'))

@app.route('/domains/delete_all', methods=['POST'])
def delete_all_domains():
    """Soft delete all domains"""
    try:
        # Get count of active domains before deletion
        active_count = Domain.query.filter_by(active=True).count()

        if active_count == 0:
            flash('No active domains to delete', 'warning')
            return redirect(url_for('domains'))

        # Set all active domains to inactive
        Domain.query.filter_by(active=True).update({'active': False})
        db.session.commit()

        flash(f'Successfully deleted {active_count} domains', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting domains: {str(e)}', 'error')

    return redirect(url_for('domains'))

@app.route('/scan/single/<int:domain_id>')
def scan_single_domain(domain_id):
    """Scan a single domain"""
    domain = Domain.query.get_or_404(domain_id)

    # Perform scan
    success, result = scanner.scan_domain(domain.hostname)

    if success:
        # Save scan result
        scan_result = create_scan_result_from_data(domain, result)
        db.session.add(scan_result)
        domain.last_scanned = datetime.utcnow()
        db.session.commit()

        flash(f'Scan completed for {domain.hostname}', 'success')
        return redirect(url_for('domain_detail', domain_id=domain.id))
    else:
        # Save failed scan result
        scan_result = ScanResult(
            domain_id=domain.id,
            scan_successful=False,
            error_message=result.get('error_message', 'Unknown error'),
            raw_output=result.get('raw_output', '')
        )
        db.session.add(scan_result)
        db.session.commit()

        flash(f'Scan failed for {domain.hostname}: {result.get("error_message", "Unknown error")}', 'error')
        return redirect(url_for('domains'))

@app.route('/scan/clear_all', methods=['POST'])
def clear_all_scans():
    """Clear all scan results"""
    try:
        # Delete all scan results
        ScanResult.query.delete()

        # Reset last_scanned for all domains
        domains = Domain.query.all()
        for domain in domains:
            domain.last_scanned = None

        db.session.commit()
        flash('All scan results cleared successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error clearing scan results: {str(e)}', 'error')

    return redirect(url_for('index'))

@app.route('/scan/bulk')
def scan_bulk():
    """Start bulk scan of all active domains"""
    # Check if there's already a running job
    existing_job = ScanJob.query.filter_by(status='running').first()
    if existing_job:
        flash('A scan job is already running', 'warning')
        return redirect(url_for('index'))

    # Get all active domains
    domains = Domain.query.filter_by(active=True).all()

    if not domains:
        flash('No active domains to scan', 'warning')
        return redirect(url_for('domains'))

    # Create scan job
    job = ScanJob(
        total_domains=len(domains),
        status='pending'
    )
    db.session.add(job)
    db.session.commit()

    # Start background scan
    thread = threading.Thread(target=perform_bulk_scan, args=(job.id, [d.id for d in domains]))
    thread.start()

    flash(f'Bulk scan started for {len(domains)} domains', 'success')
    return redirect(url_for('scan_results'))

@app.route('/scan/results')
def scan_results():
    """Show scan results with filtering and sorting"""
    page = request.args.get('page', 1, type=int)
    grade_filter = request.args.get('grade')
    deprecated_filter = request.args.get('deprecated')
    per_page = 20

    # Build query
    query = db.session.query(ScanResult).join(Domain).filter(Domain.active == True)

    # Apply filters
    if grade_filter:
        query = query.filter(ScanResult.security_grade == grade_filter)

    if deprecated_filter == 'true':
        query = query.filter(ScanResult.has_deprecated_protocols == True)
    elif deprecated_filter == 'false':
        query = query.filter(ScanResult.has_deprecated_protocols == False)

    # Order by scan date (most recent first)
    query = query.order_by(ScanResult.scan_date.desc())

    # Paginate
    results = query.paginate(page=page, per_page=per_page, error_out=False)

    # Get current job status
    current_job = ScanJob.query.filter_by(status='running').first()

    return render_template('scan_results.html', 
                         results=results,
                         current_job=current_job,
                         grade_filter=grade_filter,
                         deprecated_filter=deprecated_filter)

@app.route('/domain/<int:domain_id>')
def domain_detail(domain_id):
    """Show detailed information for a specific domain"""
    domain = Domain.query.get_or_404(domain_id)

    # Get latest scan result
    latest_scan = ScanResult.query.filter_by(domain_id=domain.id).order_by(
        ScanResult.scan_date.desc()
    ).first()

    # Get scan history
    scan_history = ScanResult.query.filter_by(domain_id=domain.id).order_by(
        ScanResult.scan_date.desc()
    ).limit(10).all()

    return render_template('domain_detail.html',
                         domain=domain,
                         latest_scan=latest_scan,
                         scan_history=scan_history)

@app.route('/documentation')
def documentation():
    """Show documentation page"""
    return render_template('documentation.html')

@app.route('/export/summary')
def export_summary():
    """Export summary report as CSV"""
    # Get all latest scan results
    latest_scans = db.session.query(ScanResult).join(Domain).filter(
        Domain.active == True
    ).order_by(Domain.hostname, ScanResult.scan_date.desc()).all()

    # Group by domain to get latest scan for each
    domain_scans = {}
    for scan in latest_scans:
        if scan.domain.hostname not in domain_scans:
            domain_scans[scan.domain.hostname] = scan

    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([
        'Hostname',
        'Last Scanned',
        'Security Grade',
        'Security Score',
        'SSLv2 Enabled',
        'SSLv3 Enabled',
        'TLSv1.0 Enabled',
        'TLSv1.1 Enabled',
        'TLSv1.2 Enabled',
        'TLSv1.3 Enabled',
        'Has Deprecated Protocols',
        'Heartbleed Vulnerable',
        'Weak Ciphers Count',
        'Certificate Issuer',
        'Certificate Expires'
    ])

    # Write data
    for hostname, scan in domain_scans.items():
        writer.writerow([
            hostname,
            scan.scan_date.strftime('%Y-%m-%d %H:%M:%S') if scan.scan_date else '',
            scan.security_grade or '',
            scan.security_score or '',
            'Yes' if scan.sslv2_enabled else 'No',
            'Yes' if scan.sslv3_enabled else 'No',
            'Yes' if scan.tlsv1_0_enabled else 'No',
            'Yes' if scan.tlsv1_1_enabled else 'No',
            'Yes' if scan.tlsv1_2_enabled else 'No',
            'Yes' if scan.tlsv1_3_enabled else 'No',
            'Yes' if scan.has_deprecated_protocols else 'No',
            'Yes' if scan.heartbleed_vulnerable else 'No',
            scan.weak_ciphers_count or 0,
            scan.cert_issuer or '',
            scan.cert_not_after.strftime('%Y-%m-%d') if scan.cert_not_after else ''
        ])

    # Create response
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=ssl_summary_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

    return response

@app.route('/export/detailed')
def export_detailed():
    """Export detailed report as CSV"""
    # Get all scan results
    scans = db.session.query(ScanResult).join(Domain).filter(
        Domain.active == True
    ).order_by(Domain.hostname, ScanResult.scan_date.desc()).all()

    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([
        'Hostname',
        'Scan Date',
        'Security Grade',
        'Security Score',
        'SSLv2 Enabled',
        'SSLv3 Enabled',
        'TLSv1.0 Enabled',
        'TLSv1.1 Enabled',
        'TLSv1.2 Enabled',
        'TLSv1.3 Enabled',
        'Has Deprecated Protocols',
        'Heartbleed Vulnerable',
        'Secure Renegotiation',
        'Fallback SCSV Supported',
        'Compression Enabled',
        'Weak Ciphers Count',
        'Certificate Subject',
        'Certificate Issuer',
        'Certificate Signature Algorithm',
        'Certificate Key Strength',
        'Certificate Not Before',
        'Certificate Not After',
        'Supported Ciphers',
        'Scan Successful',
        'Error Message'
    ])

    # Write data
    for scan in scans:
        writer.writerow([
            scan.domain.hostname,
            scan.scan_date.strftime('%Y-%m-%d %H:%M:%S') if scan.scan_date else '',
            scan.security_grade or '',
            scan.security_score or '',
            'Yes' if scan.sslv2_enabled else 'No',
            'Yes' if scan.sslv3_enabled else 'No',
            'Yes' if scan.tlsv1_0_enabled else 'No',
            'Yes' if scan.tlsv1_1_enabled else 'No',
            'Yes' if scan.tlsv1_2_enabled else 'No',
            'Yes' if scan.tlsv1_3_enabled else 'No',
            'Yes' if scan.has_deprecated_protocols else 'No',
            'Yes' if scan.heartbleed_vulnerable else 'No',
            'Yes' if scan.secure_renegotiation else 'No',
            'Yes' if scan.fallback_scsv_supported else 'No',
            'Yes' if scan.compression_enabled else 'No',
            scan.weak_ciphers_count or 0,
            scan.cert_subject or '',
            scan.cert_issuer or '',
            scan.cert_signature_algorithm or '',
            scan.cert_key_strength or '',
            scan.cert_not_before.strftime('%Y-%m-%d') if scan.cert_not_before else '',
            scan.cert_not_after.strftime('%Y-%m-%d') if scan.cert_not_after else '',
            scan.supported_ciphers or '',
            'Yes' if scan.scan_successful else 'No',
            scan.error_message or ''
        ])

    # Create response
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=ssl_detailed_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

    return response

@app.route('/api/scan_status')
def api_scan_status():
    """API endpoint to get current scan job status"""
    job = ScanJob.query.filter_by(status='running').first()

    if job:
        return jsonify({
            'status': job.status,
            'progress': job.progress_percentage,
            'completed': job.completed_domains,
            'total': job.total_domains,
            'failed': job.failed_domains
        })
    else:
        return jsonify({'status': 'none'})

def create_scan_result_from_data(domain, scan_data):
    """Create ScanResult object from scan data"""
    protocols = scan_data.get('protocols', {})
    certificate = scan_data.get('certificate', {})
    vulnerabilities = scan_data.get('vulnerabilities', {})
    security_features = scan_data.get('security_features', {})
    ciphers = scan_data.get('ciphers', [])

    # Count weak ciphers
    weak_ciphers_count = sum(1 for cipher in ciphers if cipher.get('is_weak', False))

    # Check for deprecated protocols
    has_deprecated = (protocols.get('sslv2', False) or 
                     protocols.get('sslv3', False) or 
                     protocols.get('tlsv1_0', False) or 
                     protocols.get('tlsv1_1', False))

    scan_result = ScanResult(
        domain_id=domain.id,
        sslv2_enabled=protocols.get('sslv2', False),
        sslv3_enabled=protocols.get('sslv3', False),
        tlsv1_0_enabled=protocols.get('tlsv1_0', False),
        tlsv1_1_enabled=protocols.get('tlsv1_1', False),
        tlsv1_2_enabled=protocols.get('tlsv1_2', False),
        tlsv1_3_enabled=protocols.get('tlsv1_3', False),
        heartbleed_vulnerable=vulnerabilities.get('heartbleed', False),
        compression_enabled=vulnerabilities.get('compression', False),
        fallback_scsv_supported=security_features.get('fallback_scsv', False),
        secure_renegotiation=security_features.get('secure_renegotiation', False),
        cert_signature_algorithm=certificate.get('signature_algorithm'),
        cert_key_strength=certificate.get('key_strength'),
        cert_subject=certificate.get('subject'),
        cert_issuer=certificate.get('issuer'),
        cert_not_before=certificate.get('not_before'),
        cert_not_after=certificate.get('not_after'),
        weak_ciphers_count=weak_ciphers_count,
        supported_ciphers=json.dumps(ciphers),
        has_deprecated_protocols=has_deprecated,
        raw_output=scan_data.get('raw_output', ''),
        scan_successful=scan_data.get('scan_successful', True),
        error_message=scan_data.get('error_message')
    )

    # Calculate security score
    scan_result.calculate_security_score()

    return scan_result

def perform_bulk_scan(job_id, domain_ids):
    """Perform bulk scanning in background thread"""
    with app.app_context():
        job = ScanJob.query.get(job_id)
        job.status = 'running'
        job.started_at = datetime.utcnow()
        db.session.commit()

        try:
            for domain_id in domain_ids:
                domain = Domain.query.get(domain_id)
                if not domain:
                    continue

                # Perform scan
                success, result = scanner.scan_domain(domain.hostname)

                if success:
                    # Save scan result
                    scan_result = create_scan_result_from_data(domain, result)
                    db.session.add(scan_result)
                    domain.last_scanned = datetime.utcnow()
                    job.completed_domains += 1
                else:
                    # Save failed scan result
                    scan_result = ScanResult(
                        domain_id=domain.id,
                        scan_successful=False,
                        error_message=result.get('error_message', 'Unknown error'),
                        raw_output=result.get('raw_output', '')
                    )
                    db.session.add(scan_result)
                    job.failed_domains += 1

                db.session.commit()

            job.status = 'completed'
            job.completed_at = datetime.utcnow()
            db.session.commit()

        except Exception as e:
            job.status = 'failed'
            job.completed_at = datetime.utcnow()
            db.session.commit()
            app.logger.error(f"Bulk scan failed: {e}")