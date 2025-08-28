from app.models import ReviewCategories, CourseReview, Course
from app.views_dependency import *
import json
from collections import Counter

@login_required(redirect_field_name="origin")
@utils.check_user_access(redirect_url="/logout/")
@logger.secure_view()
def coursesOverview(request):
    bar_display = utils.get_sidebar_and_navbar(
        request.user, navbar_name="课程测评", title_name="课程评价"
    )
    json_data = [
        {'category':'德', 'courses': []},
        {'category':'智', 'courses': []},
        {'category':'体', 'courses': []},
        {'category':'美', 'courses': []},
        {'category':'劳', 'courses': []},
    ]
    all_courses = ReviewCategories.objects.all().values_list('id', 'course_name', 'course_type')
    for cid, name, category in all_courses:
        category = Course.CourseType.labels[category]
        for item in json_data:
            if item['category'] == category:
                review_count = CourseReview.objects.filter(course__id=cid).count()
                item['courses'].append({'id': cid, 'name': name, 'review_count': review_count})
                break
    json_str = json.dumps(json_data, ensure_ascii=False)
    print(json_str)

    vars = {
        "bar_display": bar_display,
        "json_data": json_str,
    }
    return render(request, "review/coursesOverview.html", vars)

def getCourseInfo(request):
    """返回课程的评分统计数据

    Args:
        request (_type_): _description_

    Returns:
        json {
        'overall': {
            'recommend': [0-5], 
            'content': [0-5], 
            'workload': [0-5],
            'grade': [0-5]
        }
        'semesters': [
            {
                'name': '2023-2024-1',
                'recommend': [0-5], 
                'content': [0-5], 
                'workload': [0-5],
                'grade': [0-5]
            }
        ]
    """
    courseID = request.GET.get("id", None)
    REVIEW_PER_PAGE = 5

    if not courseID:
        return JsonResponse({"error": "缺少参数"}, status=400)
    
    try:
        course = ReviewCategories.objects.get(id=courseID)
    except ReviewCategories.DoesNotExist:
        return JsonResponse({"error": "课程不存在"}, status=400)
    
    reviews = CourseReview.objects.filter(course=course).values_list("semester","school_year", "rating_recommend", "rating_content", "rating_workload", "rating_grade")
    reviews_formated = {}
    conversion = {'Spring': 1, 'Fall' : 2}
    
    # Collect all reviews for overall calculation
    all_reviews = []
    
    for semester, year, r1, r2, r3, r4 in reviews:
        semester_s = f"{year}-{year+1}-{conversion[semester]}"
        if semester_s not in reviews_formated:
            reviews_formated[semester_s] = []
        reviews_formated[semester_s].append((r1, r2, r3, r4))
        all_reviews.append((r1, r2, r3, r4))
    
    # Calculate overall averages
    def calculate_average(ratings_list, index):
        values = [rating[index] for rating in ratings_list if rating[index] is not None]
        return round(sum(values) / len(values), 1) if values else 0
    
    overall = {
        'recommend': calculate_average(all_reviews, 0),
        'content': calculate_average(all_reviews, 1),
        'workload': calculate_average(all_reviews, 2),
        'grade': calculate_average(all_reviews, 3)
    }
    
    # Calculate semester averages
    semesters = []
    for semester_name, semester_reviews in reviews_formated.items():
        semester_data = {
            'name': semester_name,
            'recommend': calculate_average(semester_reviews, 0),
            'content': calculate_average(semester_reviews, 1),
            'workload': calculate_average(semester_reviews, 2),
            'grade': calculate_average(semester_reviews, 3)
        }
        semesters.append(semester_data)
    
    # Sort semesters by name for consistent ordering
    semesters.sort(key=lambda x: x['name'])

    # Handle review pagination
    total_pages = (len(reviews) + REVIEW_PER_PAGE - 1) // REVIEW_PER_PAGE

    
    return JsonResponse({"overall": overall, "semesters": semesters, "total_pages": total_pages})

def getCourseReviews(request):
    """返回课程的评价列表

    Args:
        request (_type_): _description_

    Returns:
        json {
        'reviews': [
            {
                'review': '用户名',
                'title': '标题',
                'text': '内容',
                'rating_recommend': [0-5], 
                'rating_content': [0-5], 
                'rating_workload': [0-5],
                'rating_grade': [0-5],
                'time': '2023-10-01'
            }
        ]
    """
    courseID = request.GET.get("id", None)
    page = int(request.GET.get("page", 1))
    REVIEW_PER_PAGE = 5

    if not courseID:
        return JsonResponse({"error": "缺少参数"}, status=400)
    
    try:
        course = ReviewCategories.objects.get(id=courseID)
    except ReviewCategories.DoesNotExist:
        return JsonResponse({"error": "课程不存在"}, status=400)
    
    reviews = CourseReview.objects.filter(course=course).order_by('-time')
    total_reviews = reviews.count()
    total_pages = (total_reviews + REVIEW_PER_PAGE - 1) // REVIEW_PER_PAGE

    if total_pages == 0:
        return JsonResponse({"reviews": []})

    if page < 1 or page > total_pages:
        return JsonResponse({"error": "页码超出范围"}, status=400)
    
    start = (page - 1) * REVIEW_PER_PAGE
    end = start + REVIEW_PER_PAGE
    reviews_page = reviews[start:end]

    reviews_list = []
    for review in reviews_page:
        semester_s = f"{review.school_year}-{review.school_year + 1}-{1 if review.semester == 'Spring' else 2}"
        reviews_list.append({
            'reviewer': review.reviewer.get_username() if not review.anonymous_flag else "匿名用户",
            'title': review.title,
            'text': review.text,
            'rating_recommend': review.rating_recommend,
            'rating_content': review.rating_content,
            'rating_workload': review.rating_workload,
            'rating_grade': review.rating_grade,
            'time': review.time.strftime("%Y-%m-%d"),
            'semester': semester_s,
            'teacher': review.teacher,
            'likes': review.likes,
            'dislikes': review.dislikes,
        })
    
    return JsonResponse({"reviews": reviews_list})